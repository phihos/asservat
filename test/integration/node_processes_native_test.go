package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	processcodec "asservat.local/asservat/internal/adapters/processes"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const processArgCanary = "ASSERVAT_PROCESS_ARG_CANARY_7a0f"
const processEnvCanary = "ASSERVAT_PROCESS_ENV_CANARY_3c9d"

type nativeProcessSink struct {
	mu     sync.Mutex
	result collector.ProcessResult
	peer   collector.Identity
	body   []byte
	calls  int
	done   chan struct{}
}

func (s *nativeProcessSink) DeliverProcesses(_ context.Context, peer collector.Identity, result collector.ProcessResult, body io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(body, artifact.ProcessNativeLimit+1))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls == 1 {
		s.result, s.peer, s.body = result, peer, raw
		close(s.done) // Preserve the original failure receipt as well as success.
	}
	if err != nil || int64(len(raw)) > artifact.ProcessNativeLimit || s.calls != 1 {
		return artifact.ErrInvalid
	}
	return nil
}

func nativeProcessesPod(image string) *core.Pod {
	p := restrictedPod("process-workload", image)
	p.Spec.Containers[0].Name = "first"
	p.Spec.Containers[0].Args = []string{"while :; do sleep 3600; done", "--", processArgCanary}
	p.Spec.Containers[0].Env = []core.EnvVar{{Name: "PROCESS_FIXTURE_CANARY", Value: processEnvCanary}}
	second := *p.Spec.Containers[0].DeepCopy()
	second.Name = "second"
	p.Spec.Containers = append(p.Spec.Containers, second)
	return p
}

func checkNativeProcesses(w collector.Work, peer collector.Identity, result collector.ProcessResult, raw []byte, pod *core.Pod) (artifact.ProcessInventory, error) {
	var zero artifact.ProcessInventory
	if w.Processes == nil || !w.Processes.Valid() || !result.Valid() || pod == nil || len(pod.Spec.Containers) != 2 || len(pod.Status.ContainerStatuses) != 2 || len(pod.Spec.InitContainers) != 0 || len(pod.Spec.EphemeralContainers) != 0 ||
		result.Failure != "" || result.WorkID != w.ID || result.CaptureID != w.Processes.CaptureID || result.ExpectationDigest != w.Processes.ExpectationDigest || result.PodUID != string(pod.UID) || result.PodUID != w.Processes.Request.Pin.UID || result.NodeUID != peer.NodeUID || result.NodeBootID != peer.BootID || result.NativeBytes != int64(len(raw)) || result.StartedAt.Before(w.Processes.Request.NotBefore) || result.CompletedAt.After(w.Processes.Request.Deadline) || bytes.Contains(raw, []byte(processArgCanary)) || bytes.Contains(raw, []byte(processEnvCanary)) {
		return zero, fmt.Errorf("process result source, bound or metadata-only contract failed")
	}
	native, err := processcodec.DecodeProcesses(raw)
	if err != nil || native.PodUID != string(pod.UID) || native.NodeUID != peer.NodeUID || native.NodeBootID != peer.BootID || native.Mode != artifact.ProcessAll || native.StartedAt.Before(result.StartedAt) || native.CompletedAt.After(result.CompletedAt) || len(native.Origins) != 2 {
		return zero, fmt.Errorf("native process inventory source or completeness failed")
	}
	names := map[string]bool{}
	for _, container := range pod.Spec.Containers {
		names[container.Name] = true
	}
	current := map[string]core.ContainerStatus{}
	for _, status := range pod.Status.ContainerStatuses {
		if !names[status.Name] || !status.Ready || status.State.Running == nil || status.RestartCount < 0 || !strings.HasPrefix(status.ContainerID, "containerd://") || current[status.ContainerID].ContainerID != "" {
			return zero, fmt.Errorf("current process container metadata unavailable")
		}
		current[status.ContainerID] = status
		delete(names, status.Name)
	}
	for _, origin := range native.Origins {
		status, ok := current[origin.RuntimeID]
		if !ok || origin.Outcome != "observed" || origin.RestartCount != uint32(status.RestartCount) {
			return zero, fmt.Errorf("process runtime origin replaced or missing")
		}
		main := false
		for _, row := range native.Processes {
			if row.Identity.RuntimeID == origin.RuntimeID && row.Main && row.Identity.HostPID == origin.MainPID {
				main = row.NamespacePID == 1 && row.UID == 65532 && row.ExecutablePath == "/bin/sh"
			}
		}
		if !main {
			return zero, fmt.Errorf("current container main identity missing")
		}
	}
	for _, gap := range native.Gaps {
		if gap != "socketOwnersUnsupported" && gap != "processGone" {
			return zero, fmt.Errorf("process source incomplete")
		}
	}
	return native, nil
}

// This is actual chart/node/containerd/kernel/TLS component qualification on a
// guarded disposable VM. Its channel authority is synthetic; it does not prove
// SQL admission, grants, catalog verification, public queries or installation.
func processCaptureNative(t *testing.T, ctx context.Context, k kubernetes.Interface, ch *delivery.NodeChannel, view delivery.NodeView, namespace, image, work, collectorNamespace string, results map[string]any) {
	t.Helper()
	created, err := k.CoreV1().Pods(namespace).Create(ctx, nativeProcessesPod(image), meta.CreateOptions{})
	if err != nil {
		t.Fatal("create Restricted process workload", err)
	}
	readyBy := time.Now().Add(time.Minute)
	for {
		current, err := k.CoreV1().Pods(namespace).Get(ctx, created.Name, meta.GetOptions{})
		if err != nil || current.UID != created.UID {
			t.Fatal("original process workload unavailable", err)
		}
		if len(current.Status.ContainerStatuses) == 2 && current.Status.ContainerStatuses[0].Ready && current.Status.ContainerStatuses[1].Ready {
			created = current
			break
		}
		if ctx.Err() != nil || time.Now().After(readyBy) {
			t.Fatal("process workload did not become Ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	ns, err := k.CoreV1().Namespaces().Get(ctx, namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current, ok := ch.NodeByUID(view.Identity.NodeUID)
	if !ok || !current.RecorderAvailable(collector.MechanismProcesses) || current.Identity != view.Identity || created.Spec.NodeName != current.Identity.NodeName {
		t.Fatal("original process mechanism/node unavailable")
	}
	sink := &nativeProcessSink{done: make(chan struct{})}
	ch.SetProcessSink(sink)
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now().UTC()
	deadline, _ := call.Deadline()
	request := collector.ProcessCapture{CaptureID: uuid.NewString(), CollectorEpoch: current.Identity.Epoch, ExpectationDigest: artifact.Digest{1}, Request: execution.ProcessSnapshotRequest{Pin: artifact.PinnedPod{Namespace: namespace, NamespaceUID: string(ns.UID), Name: created.Name, UID: string(created.UID), NodeName: created.Spec.NodeName}, NodeUID: current.Identity.NodeUID, NodeBootID: current.Identity.BootID, Mode: artifact.ProcessAll, NativeLimit: artifact.ProcessNativeLimit, NotBefore: started, Deadline: deadline}}
	// Retain content-free original facts even when the one upload never arrives
	// or its original failure receipt is refused by the success assertions.
	origins := make([]map[string]any, 0, len(created.Status.ContainerStatuses))
	for _, status := range created.Status.ContainerStatuses {
		origins = append(origins, map[string]any{"name": status.Name, "runtimeID": status.ContainerID, "restartCount": status.RestartCount, "ready": status.Ready})
	}
	attempt := map[string]any{"stage": "enqueue", "request": request, "callerUntil": deadline, "node": current.Identity, "podUID": created.UID, "containerOrigins": origins}
	results["processesAttempt"] = attempt
	w, err := ch.EnqueueProcesses(call, request, started.Add(3*time.Second))
	if err != nil {
		t.Fatal("enqueue original process request", err)
	}
	attempt["stage"], attempt["workID"], attempt["sequence"], attempt["startBy"] = "awaiting-upload", w.ID, w.Sequence, w.NotAfter
	select {
	case <-sink.done:
	case <-call.Done():
		attempt["stage"], attempt["elapsedSeconds"] = "upload-missing", time.Since(started).Seconds()
		t.Fatal("original process upload missing within five-second caller bound")
	}
	elapsed := time.Since(started)
	sink.mu.Lock()
	r, raw, peer, calls := sink.result, bytes.Clone(sink.body), sink.peer, sink.calls
	sink.mu.Unlock()
	attempt["stage"], attempt["result"], attempt["peer"], attempt["callCount"], attempt["elapsedSeconds"] = "received", r, peer, calls, elapsed.Seconds()
	// Synthetic source bytes only, retained even on validation failure.
	if err := os.WriteFile(filepath.Join(work, "processes-native.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	native, err := checkNativeProcesses(w, peer, r, raw, created)
	if err != nil || peer != current.Identity || calls != 1 || elapsed > 5*time.Second {
		t.Fatal("original process native result refused", r.Failure, err)
	}
	after, err := k.CoreV1().Pods(namespace).Get(ctx, created.Name, meta.GetOptions{})
	if err != nil || after.UID != created.UID {
		t.Fatal("original process Pod replaced", err)
	}
	if _, err := checkNativeProcesses(w, peer, r, raw, after); err != nil {
		t.Fatal("runtime origins changed after collection", err)
	}
	collectorPod, err := k.CoreV1().Pods(collectorNamespace).Get(ctx, current.Identity.PodName, meta.GetOptions{})
	if err != nil || string(collectorPod.UID) != current.Identity.PodUID {
		t.Fatal("original collector resources unavailable", err)
	}
	t.Cleanup(func() {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		if sink.calls != 1 {
			t.Error("original process upload was repeated", sink.calls)
		}
	})
	results["processes"] = map[string]any{"bytes": len(raw), "sha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "elapsedSeconds": elapsed.Seconds(), "startedAt": r.StartedAt, "completedAt": r.CompletedAt, "origins": native.Origins, "processRecords": len(native.Processes), "gaps": native.Gaps, "podUID": created.UID, "nodeUID": peer.NodeUID, "nodeBootID": peer.BootID, "containersBefore": created.Status.ContainerStatuses, "containersAfter": after.Status.ContainerStatuses, "collectorConfiguredResources": collectorPod.Spec.Containers[0].Resources, "metadataCanariesAbsent": true, "configuredNativeCap": artifact.ProcessNativeLimit}
}
