package evidence

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// contextFixture is a neutral registered source and its copy receipts.
type contextFixture struct {
	now    time.Time
	e      artifact.ContextExpectation
	copies artifact.Copies
}

func newContextFixture(t *testing.T) *contextFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	f := &contextFixture{now: now, e: artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, NodeUID: "node", NodeBootID: id, PodUID: "pod", Namespace: "app", NamespaceUID: "namespace", WorkloadUID: "workload", CollectorVersion: "test", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "context", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.example.test", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}}
	for i := range f.copies {
		f.copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if f.e.Validate() != nil || f.copies.Validate(f.e.Registration) != nil {
		t.Fatal("invalid test fixture")
	}
	return f
}
