package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

type snapshotRecordingQueue struct{ got []collector.SourceSnapshot }

func (q *snapshotRecordingQueue) NodeByName(string) (delivery.NodeView, bool) {
	return delivery.NodeView{}, false
}
func (q *snapshotRecordingQueue) EnqueuePacket(string, collector.PacketCapture, time.Time) (collector.Work, error) {
	panic("snapshot attempted finite capture")
}
func (q *snapshotRecordingQueue) EnqueueSourceSnapshot(_ context.Context, s collector.SourceSnapshot) (collector.Work, error) {
	q.got = append(q.got, s)
	return collector.Work{ID: s.Request.SnapshotID}, nil
}

func TestRegionalSourceSnapshotTransfersPreparedOutputOnceWithoutFiniteCapture(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := sourceOwnerPermit(now)
	p.Binding.AudienceDigest = [32]byte{7}
	p.Binding.ActionID = "a0123456789abcdef01234567"
	q := &snapshotRecordingQueue{}
	h := &ConnectorRecordings{nodes: q, held: make(map[string]*heldRecording), now: func() time.Time { return now }}
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(delivery.SourceBindingDigest(p.Binding)), SourceID: p.Binding.SourceID, Fence: p.Binding.Fence, SnapshotID: p.Binding.SourceID, SourceStartedAt: p.StartedAt, SourceHardUntil: p.HardUntil, T0: now, IssuedAt: now, StartBy: now.Add(time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	digest := artifact.Digest{1}
	id := p.Binding.SourceID
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, NativeType: artifact.PCAPNGArtifact, Snapshot: &request, CaptureUID: id, PodUID: p.Binding.PodUID, Namespace: "app", NamespaceUID: id, WorkloadUID: id, ActionID: p.Binding.ActionID, CaseID: id, OccurrenceID: id, CollectorVersion: "synthetic-test", CollectorImageDigest: digest, RecipeDigest: digest, PlanDigest: digest, DataClass: "metadata", PurposeRef: "source-snapshot", TriggeredAt: now,
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: request.MaxBytes, AnchorAt: artifact.SourceSnapshotAnchor(request), WriteUntil: request.ProcessingUntil, ExpiresAt: now.Add(120 * time.Second), DeleteBy: now.Add(180 * time.Second)},
		Audience:     []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id, BasisDigest: digest}}, RequestedAgeSeconds: 120, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 60, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: digest}},
		Lifecycle: &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: request.SourceID, SourceStartedAt: request.SourceStartedAt, SnapshotID: request.SnapshotID, RequestedBefore: request.Before, After: 0, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}}}
	bindingJSON, _ := json.Marshal(p.Binding)
	scope := []byte(`{"schemaVersion":"source-window/v1"}`)
	e.PlanDigest = artifact.Digest(sha256.Sum256(scope))
	e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: scope, Binding: bindingJSON}
	if err := e.Validate(); err != nil {
		t.Fatal("invalid API snapshot fixture", err)
	}
	output := h.Prepare(&objectstore.PreparedArtifact{}, e)
	snapshot := collector.SourceSnapshot{AttemptID: e.Registration.Location.AttemptID, WriterPodUID: p.Binding.SourceID, WriterEpoch: p.Binding.SourceID, Binding: p.Binding, CaptureID: e.CaptureUID, ExpectationDigest: [32]byte(evidence.ContextExpectationDigest(e)), Request: request}
	badNode := snapshot
	badNode.Binding.NodeUID = "22222222-2222-4222-8222-222222222222"
	badBoot := snapshot
	badBoot.Binding.BootID = "22222222-2222-4222-8222-222222222222"
	for _, bad := range []collector.SourceSnapshot{badNode, badBoot} {
		if _, err := output.StartSourceSnapshot(t.Context(), bad); err == nil || len(q.got) != 0 || output.prepared == nil {
			t.Fatal("changed physical source consumed API output", err)
		}
	}
	bad := snapshot
	bad.ExpectationDigest[0] ^= 1
	ctx, cancel := context.WithDeadline(t.Context(), request.StartBy)
	defer cancel()
	if _, err := output.StartSourceSnapshot(ctx, bad); err == nil || len(q.got) != 0 || output.prepared == nil {
		t.Fatal("bad expectation consumed prepared authority", err)
	}
	if queued, err := output.StartSourceSnapshot(ctx, snapshot); err != nil || !queued.Equal(now) || len(q.got) != 1 || q.got[0] != snapshot || output.prepared != nil {
		t.Fatal("source snapshot was not exact single-use", queued, err, q.got)
	}
	if _, err := output.StartSourceSnapshot(ctx, snapshot); err == nil || len(q.got) != 1 {
		t.Fatal("duplicate start queued twice", err)
	}
	if h.held[e.CaptureUID].snapshot == nil || h.held[e.CaptureUID].expectation.Recording != nil {
		t.Fatal("lost existing-source operation")
	}
}
