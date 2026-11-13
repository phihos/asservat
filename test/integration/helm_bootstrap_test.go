package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
)

type helmBootstrapFixture struct {
	RegistryConfig   map[string]any `json:"registryConfig"`
	ProductBinary    string         `json:"productBinary"`
	ChartArchive     string         `json:"chartArchive"`
	NodeA            string         `json:"nodeA"`
	NodeAUID         string         `json:"nodeAUID"`
	NodeB            string         `json:"nodeB"`
	NodeBUID         string         `json:"nodeBUID"`
	ObjectStoreImage string         `json:"objectStoreImage,omitempty"`
	KeyServiceImage  string         `json:"keyServiceImage,omitempty"`
	PostgresImage    string         `json:"postgresImage,omitempty"`
	IdentityImage    string         `json:"identityImage,omitempty"`
}

func helmBootstrapPublicInput(d contracts.InitialBootstrap) contracts.InitialBootstrapInput {
	pemRoots := func(roots [][]byte) string {
		var b bytes.Buffer
		for _, r := range roots {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: r})
		}
		return b.String()
	}
	return contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: d.Name, BootstrapNamespace: d.BootstrapNamespace, TargetNamespace: d.TargetNamespace, RunnerAccount: d.Name + "-bootstrap-runner", Image: d.Image, RegistryAuthentication: contracts.InitialRegistryAuthentication,
		Kubernetes: contracts.InitialBootstrapEndpointInput{Endpoint: d.Kubernetes.Endpoint},
		Postgres:   contracts.InitialBootstrapPostgresInput{Host: d.Postgres.Host, Port: d.Postgres.Port, Database: d.Postgres.Database, MaxConnections: d.Postgres.MaxConnections, RootsPEM: pemRoots(d.Postgres.Roots)},
		AuditStore: contracts.InitialBootstrapAuditStoreInput{Endpoint: d.AuditStore.Endpoint, Region: d.AuditStore.Region, Bucket: d.AuditStore.Bucket, RootsPEM: pemRoots(d.AuditStore.Roots)},
		KeyService: contracts.InitialBootstrapKeyServiceInput{Endpoint: d.KeyService.Endpoint, AuditMount: d.KeyService.AuditMount, AuditKey: d.KeyService.AuditKey, RootsPEM: pemRoots(d.KeyService.Roots)}, Fleet: d.Fleet, Providers: d.Providers}
}
func helmBootstrapValues(input contracts.InitialBootstrapInput) map[string]any {
	b, _ := json.Marshal(input)
	var values map[string]any
	_ = json.Unmarshal(b, &values)
	for _, k := range []string{"format", "bootstrapNamespace", "runnerAccount", "registryAuthentication"} {
		delete(values, k)
	}
	values["enabled"] = true
	values["registrySecret"] = "operator-pull"
	values["secrets"] = map[string]any{"producer": "operator-producer", "schema": "operator-ddl", "retirement": "operator-retirement"}
	return map[string]any{"mode": "hub", "runtime": map[string]any{"enabled": false}, "bootstrap": values}
}
func helmBootstrapWriteValues(t *testing.T, path string, values map[string]any) {
	t.Helper()
	b, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func helmBootstrapCommand(ctx context.Context, x helmBootstrapFixture, kubeconfig, namespace, values string) error {
	timeout := "6m"
	if os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		timeout = "20m"
	}
	command := exec.CommandContext(ctx, "helm", "upgrade", "--install", "asservat", x.ChartArchive, "--kubeconfig", kubeconfig, "--namespace", namespace, "--values", values, "--wait", "--timeout", timeout, "--history-max", "4")
	// Helm only receives public values and references; its output is not a
	// credential transport. Keep even unexpected diagnostics bounded.
	output := &helmBootstrapOutput{}
	command.Stdout = output
	command.Stderr = output
	if e := command.Run(); e != nil {
		return fmt.Errorf("Helm command: %w: %s", e, output.Bytes())
	}
	return nil
}

type helmBootstrapOutput struct{ bytes.Buffer }

func (b *helmBootstrapOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 32<<10 {
		p = p[:min(len(p), (32<<10)-b.Len())]
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func helmBootstrapRun(t *testing.T, ctx context.Context, api kubernetes.Interface, kubeconfig string, d contracts.InitialBootstrap, x helmBootstrapFixture, values string, flipNodes, wantSuccess bool) *core.Pod {
	t.Helper()
	bound := 6 * time.Minute
	if os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
		bound = 20 * time.Minute
	}
	runCtx, stop := context.WithTimeout(ctx, bound)
	defer stop()
	name := d.Name + "-bootstrap"
	list, e := api.CoreV1().Pods(d.BootstrapNamespace).List(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + name})
	if e != nil || len(list.Items) != 0 {
		t.Fatal("expected no prior fixed hook before invocation", e)
	}
	watcher, e := api.CoreV1().Pods(d.BootstrapNamespace).Watch(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + name, ResourceVersion: list.ResourceVersion})
	if e != nil {
		t.Fatal(e)
	}
	defer watcher.Stop()
	done := make(chan error, 1)
	go func() { done <- helmBootstrapCommand(runCtx, x, kubeconfig, d.BootstrapNamespace, values) }()
	commandJoined := false
	defer func() {
		stop()
		if !commandJoined {
			<-done
		}
	}()
	var original types.UID
	var terminal *core.Pod
	var commandErr error
	flipped := false
	runtimeRegistry := false
	defer func() {
		if t.Failed() && original != "" {
			helmBootstrapFailureLogs(t, api, d, name, original)
		}
	}()
	for !commandJoined || terminal == nil {
		select {
		case commandErr = <-done:
			commandJoined = true
			if commandErr != nil && wantSuccess {
				t.Fatal(commandErr)
			}
			if commandErr == nil && !wantSuccess {
				t.Fatal("invalid public input unexpectedly succeeded")
			}
			// A failed Helm invocation without a terminal Pod is not the expected
			// malformed-input regression; do not invent a terminal receipt.
		case event, ok := <-watcher.ResultChan():
			if !ok {
				t.Fatal("original hook watch ended before joined terminal")
			}
			pod, ok := event.Object.(*core.Pod)
			if !ok {
				t.Fatal("unexpected original hook watch object")
			}
			if original == "" {
				original = pod.UID
			}
			if pod.UID != original {
				t.Fatal("fixed hook was replaced during one invocation")
			}
			running := false
			for _, s := range append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
				running = running || s.State.Running != nil
			}
			if flipNodes && !flipped && running {
				if pod.Spec.NodeName != x.NodeA {
					t.Fatal("original runner did not use initially sole schedulable owned node")
				}
				cmd := exec.CommandContext(runCtx, x.ProductBinary, "installer-resume", "--kubeconfig", kubeconfig, "--namespace", d.BootstrapNamespace, "--name", d.Name)
				if err := cmd.Run(); err == nil {
					t.Fatal("actual resume CLI removed live hook")
				}
				current, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(runCtx, name, meta.GetOptions{})
				if err != nil || current.UID != original {
					t.Fatal("live CLI refusal changed original hook", err)
				}
				// Only owned fixture scheduling availability changes. The product Pod,
				// activation template and admission digest remain byte-for-byte intact.
				for _, n := range []struct {
					name, uid string
					cordon    bool
				}{{x.NodeB, x.NodeBUID, false}, {x.NodeA, x.NodeAUID, true}} {
					node, err := api.CoreV1().Nodes().Get(runCtx, n.name, meta.GetOptions{})
					if err != nil || string(node.UID) != n.uid {
						t.Fatal("owned scheduling identity changed", err)
					}
					node.Spec.Unschedulable = n.cordon
					if _, err = api.CoreV1().Nodes().Update(runCtx, node, meta.UpdateOptions{}); err != nil {
						t.Fatal("owned scheduling CAS", err)
					}
				}
				flipped = true
			}
			if os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" && !runtimeRegistry {
				proof, ready, err := helmRuntimeRegistryProof(pod, d.BootstrapNamespace, name, d.Image, original)
				if err != nil {
					t.Fatal("runtime registry original cold boundary", err)
				}
				if ready {
					helmEnableRuntimeRegistry(t, runCtx, api, x, proof)
					runtimeRegistry = true
				}
			}
			if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
				terminal = pod.DeepCopy()
			}
		case <-runCtx.Done():
			t.Fatal("original Helm invocation did not join terminal", runCtx.Err(), commandErr)
		}
	}
	if wantSuccess && (terminal.Status.Phase != core.PodSucceeded || flipNodes && !flipped) {
		t.Fatal("original hook failed its fixed chain")
	}
	if !wantSuccess && terminal.Status.Phase != core.PodFailed {
		t.Fatal("malformed-input hook lacked positive failed terminal")
	}
	if wantSuccess {
		statuses := append(append([]core.ContainerStatus{}, terminal.Status.InitContainerStatuses...), terminal.Status.ContainerStatuses...)
		if os.Getenv("ASSERVAT_HELM_BUNDLED_IDENTITY") == "1" {
			if err := helmContextTerminalValid(terminal, d.BootstrapNamespace, name, d.Image, original); err != nil {
				t.Fatal("actual bundled five-command terminal", err)
			}
		} else if len(statuses) != 4 {
			t.Fatal("fixed four commands were not all observed")
		}
		digest := strings.Split(d.Image, "@")[1]
		for _, s := range statuses {
			if s.RestartCount != 0 || s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 || !strings.HasSuffix(s.ImageID, digest) {
				t.Fatal("fixed command identity/positive exit mismatch", s.Name)
			}
		}
		if _, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(runCtx, name, meta.GetOptions{}); !apierrors.IsNotFound(e) {
			t.Fatal("hook-succeeded cleanup not observed", e)
		}
	}
	return terminal
}

// Capture bounded diagnostics before the owned fixture cleanup removes the
// failed hook. Helm's generic failed-Pod error does not identify which command
// failed. This reads only the same original Pod and its fixed product commands;
// it never reads provider Secrets or treats a diagnostic as a test outcome.
func helmBootstrapFailureLogs(t *testing.T, api kubernetes.Interface, d contracts.InitialBootstrap, name string, uid types.UID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pod, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || pod.UID != uid {
		t.Logf("original hook diagnostic unavailable: %v", err)
		return
	}
	containers := append(append([]core.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	statuses := append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	if (len(containers) != 4 && len(containers) != 5) || len(statuses) > len(containers) {
		t.Log("original hook diagnostic has unexpected command count")
		return
	}
	commands := []string{"produce", "schema", "prepare", "retire", "continue"}
	for i, c := range containers {
		if c.Name != commands[i] || c.Image != d.Image {
			t.Log("original hook diagnostic has unexpected command/image")
			return
		}
	}
	for _, status := range statuses {
		valid := false
		for _, c := range containers {
			valid = valid || c.Name == status.Name && c.Image == d.Image
		}
		if !valid {
			t.Log("original hook diagnostic has unexpected image or command identity")
			return
		}
		if status.State.Terminated != nil {
			t.Logf("original hook command %s terminated: exit=%d reason=%s", status.Name, status.State.Terminated.ExitCode, status.State.Terminated.Reason)
		} else if status.State.Waiting != nil {
			t.Logf("original hook command %s waiting: reason=%s", status.Name, status.State.Waiting.Reason)
			continue
		}
		out, err := api.CoreV1().Pods(d.BootstrapNamespace).GetLogs(name, &core.PodLogOptions{Container: status.Name, TailLines: ptr.To(int64(32)), LimitBytes: ptr.To(int64(8192))}).DoRaw(ctx)
		if err != nil {
			t.Logf("original hook command %s logs unavailable: %v", status.Name, err)
			continue
		}
		t.Logf("original hook command %s bounded output: %s", status.Name, out)
	}
}

type helmBootstrapProviderWatch struct {
	stop   func()
	values chan string
	errors chan error
	joined chan struct{}
}

func helmBootstrapWatchProvider(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, registry []byte) *helmBootstrapProviderWatch {
	t.Helper()
	list, e := api.CoreV1().Secrets("").List(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + d.Name + "-providers", Limit: 2})
	if e != nil || list.Continue != "" || len(list.Items) > 1 {
		t.Fatal("bounded original provider observation unavailable", e)
	}
	for _, s := range list.Items {
		for _, b := range s.Data {
			clear(b)
		}
		if s.Namespace == d.TargetNamespace {
			t.Fatal("provider copy existed before product admission")
		}
	}
	watch, e := api.CoreV1().Secrets("").Watch(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + d.Name + "-providers", ResourceVersion: list.ResourceVersion})
	if e != nil {
		t.Fatal(e)
	}
	w := &helmBootstrapProviderWatch{stop: watch.Stop, values: make(chan string, 1), errors: make(chan error, 1), joined: make(chan struct{})}
	expected := bytes.Clone(registry)
	go func() {
		defer close(w.joined)
		defer clear(expected)
		for event := range watch.ResultChan() {
			s, ok := event.Object.(*core.Secret)
			if !ok {
				w.errors <- fmt.Errorf("provider watch returned unexpected object")
				return
			}
			match := s.Namespace == d.TargetNamespace
			valid := s.Type == core.SecretTypeDockerConfigJson && s.Immutable != nil && *s.Immutable && len(s.Data) == 8 && bytes.Equal(s.Data[core.DockerConfigJsonKey], expected)
			for _, b := range s.Data {
				clear(b)
			}
			if match {
				if !valid {
					w.errors <- fmt.Errorf("original provider copy does not contain exact closed registry input")
				} else {
					w.values <- string(s.UID)
				}
				return
			}
		}
	}()
	return w
}
func (w *helmBootstrapProviderWatch) Close() { w.stop(); <-w.joined }
func (w *helmBootstrapProviderWatch) Take(t *testing.T, ctx context.Context) string {
	t.Helper()
	select {
	case v := <-w.values:
		return v
	case e := <-w.errors:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal("original provider Secret event missing")
	}
	return ""
}
func helmBootstrapCleanup(t *testing.T, api kubernetes.Interface, d contracts.InitialBootstrap, namespaceUID types.UID, installedPublic bool) {
	t.Helper()
	if installedPublic {
		// This selected workflow leaves a running guarded installation, retained
		// services/PVCs and regional enrollment. The bootstrap-only namespace
		// cleanup cannot uninstall that runtime. Its disposable environment belongs
		// to the existing outer harness, whose terminal receipt requires absence of
		// the owned clusters, containers, volumes, networks and images.
		t.Log("full installed public fixture cleanup owner: owned-context-harness; runtime guards and retained sources remain intact until owned environment teardown")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := d.Name + "-bootstrap"
	p, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
	if e == nil {
		e = api.CoreV1().Pods(d.BootstrapNamespace).Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID, ResourceVersion: &p.ResourceVersion}})
	}
	if e != nil && !apierrors.IsNotFound(e) {
		t.Error("owned hook cleanup", e)
		return
	}
	for ctx.Err() == nil {
		current, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			break
		}
		if err != nil || p == nil || current.UID != p.UID {
			t.Error("owned original hook cleanup observation", err)
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		t.Error("owned hook cleanup did not join")
		return
	}
	role := d.BootstrapNamespace + "-" + d.Name + "-bootstrap-runner"
	binding, err := api.RbacV1().ClusterRoleBindings().Get(ctx, role, meta.GetOptions{})
	if err == nil {
		if binding.Annotations["meta.helm.sh/release-name"] != "asservat" || binding.Annotations["meta.helm.sh/release-namespace"] != d.BootstrapNamespace {
			t.Error("refuse unrelated chart binding cleanup")
			return
		}
		err = api.RbacV1().ClusterRoleBindings().Delete(ctx, role, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Error(err)
	}
	r, err := api.RbacV1().ClusterRoles().Get(ctx, role, meta.GetOptions{})
	if err == nil {
		if r.Annotations["meta.helm.sh/release-name"] != "asservat" || r.Annotations["meta.helm.sh/release-namespace"] != d.BootstrapNamespace {
			t.Error("refuse unrelated chart role cleanup")
			return
		}
		err = api.RbacV1().ClusterRoles().Delete(ctx, role, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &r.UID}})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Error(err)
	}
	// Existing fixture helper removes only this installation's current pinned
	// guards and namespaces. Its old fixture-only administrator names are absent.
	initialBootstrapChainCleanup(t, api, d, namespaceUID, "", "")
}
