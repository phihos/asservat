package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"testing"
	"time"
)

func processingSnapshotFixture() (ProcessingSnapshot, time.Time) {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	l := artifact.Location{ClusterID: processingID(1), ArtifactID: processingID(2), AttemptID: processingID(3)}
	x := ProcessingNode{CaptureID: processingID(4), Location: l, Target: authorization.Target{ClusterID: l.ClusterID, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}, AnchorAt: n.Add(-time.Hour), DeleteBy: n.Add(time.Hour), RetireBy: n.Add(2 * time.Hour), Origin: "capture", Parents: []artifact.Location{}}
	return ProcessingSnapshot{RootID: processingID(5), Epoch: processingID(6), Sequence: 1, Complete: true, Subject: l, Nodes: []ProcessingNode{x}, Rules: []ProcessingRule{}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, n
}

func TestProcessingRequiresCompleteInitializationAndLineage(t *testing.T) {
	s, n := processingSnapshotFixture()
	if !s.Allows(n) {
		t.Fatal("complete explicit clear snapshot denied")
	}
	for _, mutate := range []func(*ProcessingSnapshot){func(x *ProcessingSnapshot) { x.Complete = false }, func(x *ProcessingSnapshot) { x.Epoch = "" }, func(x *ProcessingSnapshot) { x.Rules = nil }, func(x *ProcessingSnapshot) { x.Nodes = nil }, func(x *ProcessingSnapshot) { x.Nodes[0].Parents = nil }, func(x *ProcessingSnapshot) { x.Nodes[0].Origin = "" }} {
		x, _ := processingSnapshotFixture()
		mutate(&x)
		if x.Allows(n) {
			t.Fatal("absence became processing approval")
		}
	}
	s.Nodes[0].Origin = "derived"
	s.Nodes[0].Parents = []artifact.Location{{ClusterID: s.Subject.ClusterID, ArtifactID: processingID(99), AttemptID: processingID(98)}}
	if s.Allows(n) {
		t.Fatal("missing parent accepted")
	}
}

func TestProcessingFutureWorkloadMatchesAndChildrenInherit(t *testing.T) {
	s, n := processingSnapshotFixture()
	root := s.Nodes[0]
	rule := ProcessingRule{ID: processingID(10), Revision: 1, State: "restricted", AdministrationUntil: n.Add(time.Hour), RetireBy: n.Add(2 * time.Hour), Scope: ProcessingScope{Kind: "workloadInterval", ClusterID: root.Target.ClusterID, NamespaceUID: root.Target.NamespaceUID, WorkloadUID: root.Target.WorkloadUID, AcquiredFrom: root.AnchorAt.Add(-time.Hour), AcquiredUntil: n.Add(time.Hour)}}
	s.Rules = []ProcessingRule{rule}
	if s.Allows(n) {
		t.Fatal("existing workload evidence not restricted")
	}
	future := root
	future.AnchorAt = n.Add(30 * time.Minute)
	s.Nodes = []ProcessingNode{future}
	if s.Allows(n) {
		t.Fatal("future matching capture escaped rule")
	}
	s.Nodes = []ProcessingNode{root}
	child := root
	child.CaptureID = processingID(20)
	child.Location.ArtifactID = processingID(21)
	child.Location.AttemptID = processingID(22)
	child.Target.WorkloadUID = "different-workload"
	child.Origin = "derived"
	child.Parents = []artifact.Location{root.Location}
	s.Subject = child.Location
	s.Nodes = append(s.Nodes, child)
	if s.Allows(n) {
		t.Fatal("new child ID escaped parent restriction")
	}
	s.Rules[0].State = "releasePending"
	if s.Allows(n) {
		t.Fatal("unacknowledged release allowed")
	}
	s.Rules[0].State = "released"
	if s.Allows(n) {
		t.Fatal("unacknowledged release state allowed")
	}
	s.Rules[0].ReleaseAcknowledged = true
	if !s.Allows(n) {
		t.Fatal("exact acknowledged release failed")
	}
	s.Nodes[0].Origin = "derived"
	s.Nodes[0].Parents = []artifact.Location{child.Location}
	if s.Allows(n) {
		t.Fatal("cyclic lineage accepted")
	}
}

func TestProcessingExpiredAdministrativeCoverageDoesNotRelease(t *testing.T) {
	s, n := processingSnapshotFixture()
	rule := ProcessingRule{ID: processingID(20), Revision: 1, State: "restricted", Scope: ProcessingScope{Kind: "artifact", Location: s.Subject}, AdministrationUntil: n.Add(-time.Hour), RetireBy: n.Add(-time.Minute)}
	s.Rules = []ProcessingRule{rule}
	if !rule.Valid() {
		t.Fatal("retained historical restriction must remain representable")
	}
	if s.Allows(n) {
		t.Fatal("expired administrative coverage became an implicit release")
	}
	s.Rules[0].Revision = 2
	s.Rules[0].State = "released"
	if s.Allows(n) {
		t.Fatal("ordinary approval or state label replaced independent release")
	}
	s.Rules[0].ReleaseAcknowledged = true
	if !s.Allows(n) {
		t.Fatal("independently acknowledged historical release not recognized")
	}
}
