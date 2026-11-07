package live

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

func TestManualLiveObservedReplyBindsOnlyOriginalRequest(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	other := "22222222-2222-4222-8222-222222222222"
	now := time.Now()
	m := collector.ManualLiveSource{RootID: id, ExecutorPodUID: id, ExecutorEpoch: id, CaptureID: id, AttemptID: id, ActionID: "packet", WorkID: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, StartedAt: now, HardUntil: now.Add(time.Minute), ObservationKind: "packet", ObservationSessionID: id, ObservationFence: id}
	r := collector.LiveRead{Manual: &m, Head: true, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "work", Projection: Packet, PrivacyUntil: now.Add(time.Second), Limit: 20}
	observed := collector.ManualObserved(m)
	reply := NodeReply{ObservedManual: &observed, SourceID: id, Fence: id, BootID: id, Clock: "monotonic", Sample: 1, Rows: []StampedRow{}}
	bound, e := BindManualLiveReply(r, reply)
	if e != nil || bound.Manual == nil || *bound.Manual != m || bound.ObservedManual != nil {
		t.Fatal("trusted original provenance not bound", bound, e)
	}
	for _, mode := range []string{"capture", "work", "pod", "node", "boot", "collector", "epoch", "session", "fence", "kind", "start", "end", "clock", "sample", "both", "missing", "head-row", "policy"} {
		q := r
		out := reply
		o := observed
		out.ObservedManual = &o
		switch mode {
		case "capture":
			o.CaptureID = other
		case "work":
			o.WorkID = other
		case "pod":
			o.PodUID = other
		case "node":
			o.NodeUID = other
		case "boot":
			o.BootID = other
		case "collector":
			o.CollectorPodUID = other
		case "epoch":
			o.CollectorEpoch = other
		case "session":
			o.ObservationSessionID = other
		case "fence":
			o.ObservationFence = other
		case "kind":
			o.ObservationKind = "arguments"
		case "start":
			o.StartedAt = o.StartedAt.Add(time.Millisecond)
		case "end":
			o.HardUntil = o.HardUntil.Add(time.Millisecond)
		case "clock":
			out.Clock = "boottime"
		case "sample":
			out.Sample = 0
		case "both":
			out.Manual = &m
		case "missing":
			out.ObservedManual = nil
		case "head-row":
			out.Rows = []StampedRow{{}}
		case "policy":
			q.Manual = nil
		}
		if _, e := BindManualLiveReply(q, out); e == nil {
			t.Fatal("substituted observed tuple or authority union", mode)
		}
	}
	// Only first passive inspection learns times; it supplies no rows or source
	// authority. Accepted queued/duration/write bounds are checked by the region.
	unknown := m
	unknown.StartedAt = time.Time{}
	unknown.HardUntil = time.Time{}
	r.Manual = &unknown
	r.Inspect = true
	if got, e := BindManualLiveReply(r, reply); e != nil || got.Manual == nil || *got.Manual != m {
		t.Fatal("passive original observation", got, e)
	}
}
