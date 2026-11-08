package collector

import (
	"testing"
	"time"
)

func TestManualLiveReadExclusiveBindingOriginalTimesAndPassiveInspection(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	m := ManualLiveSource{RootID: id, ExecutorPodUID: id, ExecutorEpoch: id, CaptureID: id, AttemptID: id, ActionID: "packet", WorkID: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}}
	r := LiveRead{Manual: &m, Inspect: true, Head: true, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "work", Projection: "packetMetadata", PrivacyUntil: time.Now().Add(time.Second), Limit: 20}
	if !r.Valid() || r.SourceID() != id || r.Fence() != id || r.Node() != id || r.Epoch() != id {
		t.Fatal("original passive tuple refused")
	}
	for _, mode := range []string{"mixed", "active-inspect", "invented-session", "unknown-executor", "unknown-start"} {
		q := r
		n := m
		q.Manual = &n
		switch mode {
		case "mixed":
			q.Binding = sourcePermitFixture(time.Now()).Binding
		case "active-inspect":
			q.Head = false
		case "invented-session":
			n.ObservationSessionID = id
		case "unknown-executor":
			n.ExecutorEpoch = ""
		case "unknown-start":
			q.Inspect = false
		}
		if q.Valid() {
			t.Fatal("invalid manual union", mode)
		}
	}
	m.StartedAt = time.Now()
	m.HardUntil = m.StartedAt.Add(5 * time.Minute)
	r.Inspect = false
	if !r.Valid() {
		t.Fatal("legitimate original packet maximum refused")
	}
	r.Inspect = true
	if r.Valid() {
		t.Fatal("inspection invented original times")
	}
}
