package integration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func nativeProcessCheckFixture() (collector.Work, collector.Identity, collector.ProcessResult, artifact.ProcessInventory, *core.Pod) {
	now := time.Now().UTC()
	const id = "11111111-1111-4111-8111-111111111111"
	peer := collector.Identity{NodeUID: "node", NodeName: "node-name", BootID: id, Epoch: id}
	pod := nativeProcessesPod("synthetic-busybox")
	pod.UID = "pod-uid"
	pod.Spec.NodeName = peer.NodeName
	native := artifact.ProcessInventory{Format: artifact.ProcessFormat, PodUID: string(pod.UID), NodeUID: peer.NodeUID, NodeBootID: peer.BootID, Mode: artifact.ProcessAll, StartedAt: now, CompletedAt: now, Origins: []artifact.ProcessOrigin{}, Processes: []artifact.ProcessRecord{}, Gaps: []string{"socketOwnersUnsupported"}}
	for n, c := range pod.Spec.Containers {
		runtimeID := "containerd://" + strings.Repeat(string(rune('a'+n)), 64)
		pid := uint32(100 + n)
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, core.ContainerStatus{Name: c.Name, ContainerID: runtimeID, Ready: true, RestartCount: int32(n), State: core.ContainerState{Running: &core.ContainerStateRunning{StartedAt: meta.NewTime(now)}}})
		native.Origins = append(native.Origins, artifact.ProcessOrigin{RuntimeID: runtimeID, RestartCount: uint32(n), MainPID: pid, Outcome: "observed"})
		native.Processes = append(native.Processes, artifact.ProcessRecord{Identity: artifact.ProcessIdentity{PodUID: string(pod.UID), NodeBootID: peer.BootID, RuntimeID: runtimeID, RestartCount: uint32(n), HostPID: pid, StartTimeTicks: uint64(n + 1), CgroupPath: "/synthetic/pod/container", CgroupID: uint64(n + 1)}, NamespacePID: 1, ObservedAt: now, Main: true, State: "S", UID: 65532, Threads: 1, ExecutablePath: "/bin/sh"})
	}
	w := collector.Work{ID: id, Sequence: 1, Kind: collector.WorkProcesses, NotAfter: now.Add(3 * time.Second), Processes: &collector.ProcessCapture{CaptureID: id, CollectorEpoch: id, ExpectationDigest: artifact.Digest{1}, Request: execution.ProcessSnapshotRequest{Pin: artifact.PinnedPod{Namespace: "synthetic", NamespaceUID: "namespace-uid", Name: pod.Name, UID: string(pod.UID), NodeName: peer.NodeName}, NodeUID: peer.NodeUID, NodeBootID: peer.BootID, Mode: artifact.ProcessAll, NativeLimit: artifact.ProcessNativeLimit, NotBefore: now, Deadline: now.Add(5 * time.Second)}}}
	r := collector.ProcessResult{WorkID: id, CaptureID: id, PodUID: string(pod.UID), NodeUID: peer.NodeUID, NodeBootID: peer.BootID, ExpectationDigest: artifact.Digest{1}, StartedAt: now, CompletedAt: now}
	return w, peer, r, native, pod
}

// Pure checks use synthetic facts and never collect or enter a namespace.
func TestNativeProcessProvenanceRejectsReplacementAndSensitiveContent(t *testing.T) {
	check := func(t *testing.T, mutate func(*collector.ProcessResult, *artifact.ProcessInventory, *core.Pod), valid bool) {
		t.Helper()
		w, peer, result, native, pod := nativeProcessCheckFixture()
		if mutate != nil {
			mutate(&result, &native, pod)
		}
		raw, err := json.Marshal(native)
		if err != nil {
			t.Fatal(err)
		}
		result.NativeBytes = int64(len(raw))
		if _, err := checkNativeProcesses(w, peer, result, raw, pod); (err == nil) != valid {
			t.Fatal("incorrect original source/native qualification", err)
		}
	}
	check(t, nil, true)
	for name, mutate := range map[string]func(*collector.ProcessResult, *artifact.ProcessInventory, *core.Pod){
		"replacement Pod": func(_ *collector.ProcessResult, _ *artifact.ProcessInventory, p *core.Pod) { p.UID = "replacement" },
		"replacement runtime": func(_ *collector.ProcessResult, _ *artifact.ProcessInventory, p *core.Pod) {
			p.Status.ContainerStatuses[0].ContainerID = "containerd://" + strings.Repeat("f", 64)
		},
		"changed restart": func(_ *collector.ProcessResult, _ *artifact.ProcessInventory, p *core.Pod) {
			p.Status.ContainerStatuses[0].RestartCount++
		},
		"unknown container": func(_ *collector.ProcessResult, _ *artifact.ProcessInventory, p *core.Pod) {
			p.Status.ContainerStatuses[0].Name = "other"
		},
		"wrong boot": func(r *collector.ProcessResult, _ *artifact.ProcessInventory, _ *core.Pod) {
			r.NodeBootID = "22222222-2222-4222-8222-222222222222"
		},
		"wrong original digest": func(r *collector.ProcessResult, _ *artifact.ProcessInventory, _ *core.Pod) { r.ExpectationDigest[0]++ },
		"original end": func(r *collector.ProcessResult, _ *artifact.ProcessInventory, _ *core.Pod) {
			r.CompletedAt = r.StartedAt.Add(6 * time.Second)
		},
		"argument canary": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Processes[0].ExecutablePath = "/" + processArgCanary
		},
		"environment canary": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Processes[0].ExecutablePath = "/" + processEnvCanary
		},
		"missing origin": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Origins = n.Origins[:1]
			n.Processes = n.Processes[:1]
		},
		"wrong main executable": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Processes[0].ExecutablePath = "/bin/busybox"
		},
		"wrong namespace PID": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Processes[0].NamespacePID = 2
		},
		"source unavailable": func(_ *collector.ProcessResult, n *artifact.ProcessInventory, _ *core.Pod) {
			n.Gaps = []string{"sourceUnavailable"}
		},
	} {
		t.Run(name, func(t *testing.T) { check(t, mutate, false) })
	}
}

func TestNativeProcessWorkloadKeepsCanariesInRestrictedTwoContainerScope(t *testing.T) {
	pod := nativeProcessesPod("synthetic-busybox")
	if len(pod.Spec.Containers) != 2 || !*pod.Spec.SecurityContext.RunAsNonRoot || *pod.Spec.SecurityContext.RunAsUser != 65532 || pod.Spec.HostPID || pod.Spec.ShareProcessNamespace != nil || pod.Spec.HostNetwork {
		t.Fatal("process fixture widened workload scope")
	}
	for _, c := range pod.Spec.Containers {
		if *c.SecurityContext.AllowPrivilegeEscalation || len(c.SecurityContext.Capabilities.Add) != 0 || strings.Join(c.Command, " ") != "sh -c" || c.Args[2] != processArgCanary || c.Env[0].Value != processEnvCanary || !strings.Contains(c.Args[0], "while") {
			t.Fatal("synthetic canary source or Restricted guarantee changed")
		}
	}
}
