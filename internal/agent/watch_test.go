package agent

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
)

func TestCrashes(t *testing.T) {
	terminated := func(id string, code int32, reason string) *corev1.ContainerStateTerminated {
		return &corev1.ContainerStateTerminated{ContainerID: id, ExitCode: code, Reason: reason}
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1"}}
	set := func(s ...corev1.ContainerStatus) { pod.Status.ContainerStatuses = s }
	seen := map[string]string{}

	set(corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}})
	if got := crashes(pod, seen); got != "" {
		t.Fatal("a running container crashed:", got)
	}
	// The kubelet first shows the terminated container, then its successor
	// with the termination as last state: one crash.
	set(corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Terminated: terminated("c1", 137, "OOMKilled")}})
	if got := crashes(pod, seen); got != "container app crashed: exit code 137, OOMKilled" {
		t.Fatal(got)
	}
	set(corev1.ContainerStatus{Name: "app", RestartCount: 1, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		LastTerminationState: corev1.ContainerState{Terminated: terminated("c1", 137, "OOMKilled")}})
	if got := crashes(pod, seen); got != "" {
		t.Fatal("one crash reported twice:", got)
	}
	// Also when the kubelet fills in the time of the termination later.
	pod.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = metav1.Now()
	if got := crashes(pod, seen); got != "" {
		t.Fatal("one crash reported twice:", got)
	}
	// The next crash of the same container, together with a sidecar's.
	set(corev1.ContainerStatus{Name: "app", RestartCount: 2, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: corev1.ContainerState{Terminated: terminated("c2", 1, "Error")}},
		corev1.ContainerStatus{Name: "proxy", State: corev1.ContainerState{Terminated: terminated("p1", 2, "Error")}})
	if got := crashes(pod, seen); got != "container app crashed: exit code 1, Error; container proxy crashed: exit code 2, Error" {
		t.Fatal(got)
	}
	// A clean exit and the stop of a deleted pod are no crashes.
	set(corev1.ContainerStatus{Name: "job", State: corev1.ContainerState{Terminated: terminated("j1", 0, "Completed")}})
	if got := crashes(pod, seen); got != "" {
		t.Fatal("a completed container crashed:", got)
	}
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	set(corev1.ContainerStatus{Name: "app", State: corev1.ContainerState{Terminated: terminated("c3", 143, "Error")}})
	if got := crashes(pod, seen); got != "" {
		t.Fatal("a deleted pod crashed:", got)
	}
}

func TestRingKeepsTheLastSecondsWithoutPayload(t *testing.T) {
	le := binary.LittleEndian
	stream := []byte{0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0}
	stream = le.AppendUint32(stream, 1) // Ethernet
	packet := make([]byte, 14+20+8)     // Ethernet, IPv4, UDP
	packet[12], packet[13], packet[14], packet[23] = 0x08, 0x00, 0x45, 17
	packet = append(packet, "secret payload"...)
	for second := uint32(100); second < 200; second++ {
		stream = le.AppendUint32(stream, second)
		stream = le.AppendUint32(stream, 0)
		stream = le.AppendUint32(stream, uint32(len(packet)))
		stream = le.AppendUint32(stream, uint32(len(packet)))
		stream = append(stream, packet...)
	}
	record := 16 + 14 + 20 + 8
	count := func(r *ring) (int, uint32) {
		t.Helper()
		got := r.snapshot()
		if !bytes.Equal(got[:24], stream[:24]) || (len(got)-24)%record != 0 || strings.Contains(string(got), "secret") {
			t.Fatal("snapshot is not a pcap file of bare headers")
		}
		return (len(got) - 24) / record, le.Uint32(got[24:])
	}

	r := &ring{window: 30 * time.Second, limit: 1 << 20}
	if r.snapshot() != nil {
		t.Fatal("snapshot before the stream began")
	}
	if err := r.fill(bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if n, first := count(r); n != 31 || first != 169 {
		t.Fatal("window: packets", n, "from second", first)
	}
	// A watch that was approved for payload keeps whole packets.
	r = &ring{window: 30 * time.Second, limit: 1 << 20, payload: true}
	if err := r.fill(bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if got := r.snapshot(); len(got) != 24+31*(16+len(packet)) || !strings.Contains(string(got), "secret payload") {
		t.Fatal("payload ring", len(got))
	}
	// The byte limit drops the oldest packets first.
	r = &ring{window: time.Hour, limit: 10 * record}
	if err := r.fill(bytes.NewReader(stream)); err != nil {
		t.Fatal(err)
	}
	if n, first := count(r); n != 10 || first != 190 {
		t.Fatal("limit: packets", n, "from second", first)
	}
}

// A watch for restarts reports a container that was started again, also
// after a clean exit; one for readiness a pod that was ready and no longer
// is. Neither reports the state in which a pod is first seen.
func TestRestartsAndReadiness(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1"}}
	container := func(restarts int32, last *corev1.ContainerStateTerminated) {
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", RestartCount: restarts, LastTerminationState: corev1.ContainerState{Terminated: last}}}
	}
	restart := api.Condition{Kind: api.OnRestart}
	seen := map[string]string{}
	container(3, nil)
	if got := met(restart, pod, seen); got != "" {
		t.Fatal("the restarts before the watch:", got)
	}
	if got := met(restart, pod, seen); got != "" {
		t.Fatal("no change:", got)
	}
	// The count rises before the new instance runs: the report waits for it.
	container(4, &corev1.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"})
	if got := met(restart, pod, seen); got != "" {
		t.Fatal("a restart whose new instance does not run yet:", got)
	}
	pod.Status.ContainerStatuses[0].State.Running = &corev1.ContainerStateRunning{}
	if got := met(restart, pod, seen); got != "container app was restarted: it ended with exit code 0, Completed" {
		t.Fatal(got)
	}
	// A crash watch does not report that clean exit.
	if got := met(api.Condition{}, pod, map[string]string{}); got != "" {
		t.Fatal("a clean exit as a crash:", got)
	}

	ready := func(status corev1.ConditionStatus, message string) {
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: status, Message: message}}
	}
	unready := api.Condition{Kind: api.OnNotReady}
	seen = map[string]string{}
	ready(corev1.ConditionFalse, "containers with unready status: [app]")
	if got := met(unready, pod, seen); got != "" {
		t.Fatal("a pod that was not ready when first seen:", got)
	}
	ready(corev1.ConditionTrue, "")
	if got := met(unready, pod, seen); got != "" {
		t.Fatal("a pod that became ready:", got)
	}
	ready(corev1.ConditionFalse, "containers with unready status: [app]")
	if got := met(unready, pod, seen); got != "pod is not ready any more: containers with unready status: [app]" {
		t.Fatal(got)
	}
	if got := met(unready, pod, seen); got != "" {
		t.Fatal("reported twice:", got)
	}
	// Ready again and then stopped on purpose: no report.
	ready(corev1.ConditionTrue, "")
	met(unready, pod, seen)
	now := metav1.Now()
	pod.DeletionTimestamp = &now
	ready(corev1.ConditionFalse, "")
	if got := met(unready, pod, seen); got != "" {
		t.Fatal("a deleted pod:", got)
	}
}
