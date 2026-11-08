package live

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"testing"
	"time"
)

func TestLiveManualSourceNeverInventsPolicyAcceptance(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	now := time.Now()
	manual := collector.ManualLiveSource{RootID: id, ExecutorPodUID: id, ExecutorEpoch: id, CaptureID: id, AttemptID: id, ActionID: "packets", WorkID: id, PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{3}, StartedAt: now, HardUntil: now.Add(time.Second)}
	s := Source{RootID: id, Manual: &manual, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: id}, OwnerKind: "manualSession", OwnerID: id, State: "Ready", SaveVia: "captureOutcome", Projections: []string{Packet}, LeaseUntil: now.Add(time.Second), HardUntil: now.Add(time.Second), PrivacyUntil: now.Add(time.Hour)}
	if !s.Valid(now) || s.ID() != manual.CaptureID || s.Root() != id || s.Action() != manual.ActionID {
		t.Fatal("actual manual observation binding refused")
	}
	clone := s.Clone()
	clone.Manual.WorkID = "22222222-2222-4222-8222-222222222222"
	if s.Same(clone) || s.Manual.WorkID != id {
		t.Fatal("manual identity borrowed or changed")
	}
	s.Binding = collector.SourceBinding{RootID: id}
	if s.Valid(now) {
		t.Fatal("manual and policy identity mixed")
	}
	s.Binding = collector.SourceBinding{}
	s.OwnerKind = "policy"
	if s.Valid(now) {
		t.Fatal("manual observation relabeled policy")
	}
}
