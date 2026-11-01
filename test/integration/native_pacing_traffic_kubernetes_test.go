package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// Existing context fixtures, one owned synthetic Kind, exact compiled helper
// and restricted traffic server. No bootstrap, collector, BPF or native file.
func TestNativePacingTrafficWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned single-cluster direct traffic probe not selected")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) != 1 || f.WorkerImage == "" || !f.NativeTrafficHelper.validForNode(f.Clusters[0].Pod.NodeName) {
		t.Fatal("owned traffic descriptor unavailable before probe")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	pod := restrictedPod("direct-traffic-"+custodyID(), f.WorkerImage)
	pod.Spec.AutomountServiceAccountToken = ptr.To(false)
	pod.Spec.Containers[0].Command = []string{"/provider-proxy", "signals"}
	pod.Spec.Containers[0].Args = nil
	// Match the declared native-paced target profile, independently of focus.
	pod.Spec.Containers[0].Resources = regionalWorkloadResources(true)
	pod.Spec.Containers[0].ReadinessProbe = &core.Probe{ProbeHandler: core.ProbeHandler{TCPSocket: &core.TCPSocketAction{Port: intstr.FromInt32(8080)}}, PeriodSeconds: 1, TimeoutSeconds: 1, FailureThreshold: 30}
	created, err := api.CoreV1().Pods("synthetic").Create(ctx, pod, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if err := api.CoreV1().Pods("synthetic").Delete(cleanup, created.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: ptr.To(types.UID(created.UID))}}); err != nil {
			t.Error("owned traffic Pod cleanup", err)
		}
	}()
	var current *core.Pod
	for {
		current, err = api.CoreV1().Pods("synthetic").Get(ctx, created.Name, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		ready := false
		for _, condition := range current.Status.Conditions {
			ready = ready || condition.Type == core.PodReady && condition.Status == core.ConditionTrue
		}
		if current.UID != created.UID {
			t.Fatal("traffic Pod replaced")
		}
		if ready && current.Status.PodIP != "" {
			break
		}
		if err := installedJourneyPause(ctx, 100*time.Millisecond); err != nil {
			t.Fatal("traffic Pod not ready", err)
		}
	}
	if !f.NativeTrafficHelper.validForNode(current.Spec.NodeName) {
		t.Fatal("traffic Pod left original owned node set")
	}
	node, err := api.CoreV1().Nodes().Get(ctx, current.Spec.NodeName, meta.GetOptions{})
	if err != nil || string(node.UID) != f.Clusters[0].NodeUID || node.Status.NodeInfo.BootID != f.Clusters[0].NodeBootID {
		t.Fatal("original node identity changed", err)
	}
	var observed nativeTrafficOutput
	command := exec.CommandContext(ctx, "docker", "exec", current.Spec.NodeName, "sha256sum", "/asservat-fixture-traffic")
	command.Stdout = &observed
	if err := command.Run(); err != nil {
		t.Fatal("helper hash read", err)
	}
	fields := strings.Fields(observed.String())
	if len(fields) != 2 || fields[0] != f.NativeTrafficHelper.SHA256 || fields[1] != "/asservat-fixture-traffic" {
		t.Fatal("serialized descriptor differs from actual helper bytes")
	}
	if err := nativePacingRequireTargetProfile(current); err != nil {
		t.Fatal("declared native-paced target", err)
	}
	beforeCPU, err := nativeTrafficTargetCPU(ctx, api, current)
	if err != nil {
		t.Fatal("exact target CPU baseline", err)
	}
	result, err := nativePacingNodeTraffic(ctx, f.NativeTrafficHelper, current.Spec.NodeName, current.Status.PodIP)
	afterCPU, cpuErr := nativeTrafficTargetCPU(ctx, api, current)
	delta, deltaErr := nativeTrafficCPUDelta(beforeCPU, afterCPU)
	report := struct {
		Helper                             nativeTrafficHelper
		PodUID, PodIP, NodeUID, NodeBootID string
		Result                             nativeTrafficResult
		BeforeCPU, AfterCPU                nativeTrafficCPU
		CPUDelta                           map[string]uint64
	}{f.NativeTrafficHelper, string(current.UID), current.Status.PodIP, string(node.UID), node.Status.NodeInfo.BootID, result, beforeCPU, afterCPU, delta}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	if writeErr := os.WriteFile("../results/native-traffic-probe.json", encoded, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if cpuErr != nil || deltaErr != nil {
		t.Fatal("exact target CPU measurement incomplete", cpuErr, deltaErr)
	}
	if err != nil || !result.ReceiptValid || result.Elapsed > nativeTrafficPhase {
		t.Fatal("actual direct traffic incomplete", result, err)
	}
	t.Logf("actual owned node→exact Pod: %d batches/%d records/%d bytes elapsed=%s client=%s; helper=%s", result.Batches, result.Records, result.Bytes, result.Elapsed, result.ClientElapsed, f.NativeTrafficHelper.SHA256)
}
