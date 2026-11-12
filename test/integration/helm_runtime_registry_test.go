package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type helmRuntimeCommandExit struct {
	Name         string `json:"name"`
	ExitCode     int32  `json:"exitCode"`
	RestartCount int32  `json:"restartCount"`
	ImageID      string `json:"imageID"`
}
type helmRuntimeHookProof struct {
	Namespace string                   `json:"namespace"`
	Name      string                   `json:"name"`
	UID       types.UID                `json:"uid"`
	Image     string                   `json:"image"`
	Commands  []helmRuntimeCommandExit `json:"commands"`
}

// This is a subset of the existing positive terminal checks, at the boundary
// before continuation. It permits continuation already running or a pending
// runtime Pod: neither changes the original four acknowledged exits.
func helmRuntimeRegistryProof(p *core.Pod, namespace, name, image string, uid types.UID) (helmRuntimeHookProof, bool, error) {
	var zero helmRuntimeHookProof
	if p == nil || uid == "" || p.UID != uid || p.Namespace != namespace || p.Name != name || len(p.Spec.InitContainers) != 4 || len(p.Spec.Containers) != 1 {
		return zero, false, errors.New("original five-command hook changed")
	}
	_, digest, pinned := strings.Cut(image, "@")
	if !pinned || !strings.HasPrefix(digest, "sha256:") {
		return zero, false, errors.New("original hook image unpinned")
	}
	expected := []string{"produce", "schema", "prepare", "retire"}
	proof := helmRuntimeHookProof{Namespace: namespace, Name: name, UID: uid, Image: image}
	for i, n := range expected {
		if p.Spec.InitContainers[i].Name != n || p.Spec.InitContainers[i].Image != image {
			return zero, false, errors.New("original hook command changed")
		}
		if len(p.Status.InitContainerStatuses) <= i {
			return zero, false, nil
		}
		s := p.Status.InitContainerStatuses[i]
		if s.Name != n || s.RestartCount != 0 {
			return zero, false, errors.New("original hook command identity changed")
		}
		if s.State.Terminated == nil {
			return zero, false, nil
		}
		if s.State.Terminated.ExitCode != 0 || !strings.HasSuffix(s.ImageID, digest) {
			return zero, false, errors.New("original hook command not positively complete")
		}
		proof.Commands = append(proof.Commands, helmRuntimeCommandExit{Name: n, ExitCode: s.State.Terminated.ExitCode, RestartCount: s.RestartCount, ImageID: s.ImageID})
	}
	if p.Spec.Containers[0].Name != "continue" || p.Spec.Containers[0].Image != image {
		return zero, false, errors.New("original continuation changed")
	}
	return proof, true, nil
}

func helmEnableRuntimeRegistry(t *testing.T, ctx context.Context, api kubernetes.Interface, x helmBootstrapFixture, proof helmRuntimeHookProof) {
	t.Helper()
	for _, flag := range []string{"ASSERVAT_HELM_BUNDLED_IDENTITY", "ASSERVAT_HELM_BUNDLED_POSTGRES", "ASSERVAT_HELM_BUNDLED_KEYSERVICE", "ASSERVAT_HELM_BUNDLED_OBJECTSTORE", "ASSERVAT_INSTALLER_CONTINUATION"} {
		if os.Getenv(flag) != "1" {
			t.Fatal("runtime registry handoff requires explicit all-four selection")
		}
	}
	nodes := map[string]string{x.NodeA: x.NodeAUID, x.NodeB: x.NodeBUID}
	if len(nodes) != 2 {
		t.Fatal("runtime registry handoff requires original distinct nodes")
	}
	for name, uid := range nodes {
		actual, err := api.CoreV1().Nodes().Get(ctx, name, meta.GetOptions{})
		if err != nil || string(actual.UID) != uid {
			t.Fatal("runtime registry original node changed")
		}
	}
	raw, err := json.Marshal(struct {
		OriginalHook helmRuntimeHookProof `json:"originalHook"`
		NodeUIDs     map[string]string    `json:"nodeUIDs"`
	}{proof, nodes})
	if err != nil {
		t.Fatal("runtime registry terminal proof unavailable")
	}
	script, err := filepath.Abs("../../scripts/helm_registry.py")
	if err != nil {
		t.Fatal("runtime registry helper path")
	}
	cmd := exec.CommandContext(ctx, "python3", script, "--runtime-node-access", os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	cmd.Stdin = bytes.NewReader(raw)
	output := &helmBootstrapOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		t.Fatalf("owned runtime registry handoff failed: %s", output.Bytes())
	}
	t.Log("fixture registry: original authenticated cold pulls recorded before node-configured runtime image access")
}

func TestHelmRuntimeRegistryRequiresOriginalFourAcknowledgedCommands(t *testing.T) {
	image := "registry.example/asservat@sha256:" + strings.Repeat("a", 64)
	p := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "install-bootstrap", Namespace: "bootstrap", UID: "original"}}
	for _, name := range []string{"produce", "schema", "prepare", "retire"} {
		p.Spec.InitContainers = append(p.Spec.InitContainers, core.Container{Name: name, Image: image})
		p.Status.InitContainerStatuses = append(p.Status.InitContainerStatuses, core.ContainerStatus{Name: name, ImageID: image, State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ExitCode: 0}}})
	}
	p.Spec.Containers = []core.Container{{Name: "continue", Image: image}}
	if proof, ready, err := helmRuntimeRegistryProof(p, "bootstrap", p.Name, image, p.UID); err != nil || !ready || len(proof.Commands) != 4 {
		t.Fatal("original four exits unavailable", err)
	}
	pending := p.DeepCopy()
	pending.Status.InitContainerStatuses[3].State = core.ContainerState{Running: &core.ContainerStateRunning{}}
	if _, ready, err := helmRuntimeRegistryProof(pending, "bootstrap", p.Name, image, p.UID); err != nil || ready {
		t.Fatal("retire not complete", err)
	}
	for _, change := range []func(*core.Pod){func(p *core.Pod) { p.UID = "replacement" }, func(p *core.Pod) { p.Status.InitContainerStatuses[1].State.Terminated.ExitCode = 1 }, func(p *core.Pod) { p.Status.InitContainerStatuses[2].RestartCount = 1 }, func(p *core.Pod) { p.Status.InitContainerStatuses[0].ImageID = "different" }} {
		bad := p.DeepCopy()
		change(bad)
		if _, ready, err := helmRuntimeRegistryProof(bad, "bootstrap", p.Name, image, p.UID); err == nil || ready {
			t.Fatal("changed or unknown original terminal accepted")
		}
	}
}
