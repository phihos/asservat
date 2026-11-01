package capture

import (
	"bytes"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// Synthetic accepted receipts test only repeat preference projection. SQL,
// custody, source authority and encrypted persistence are separately qualified.
func TestGroupedRecordingHistoryKeepsOnlyDeduplicatedAuthoredWindows(t *testing.T) {
	s, ports, _, caller, accepted := groupedSubmissionFixture(t)
	first := accepted.Group.Children[0].Expectation
	policy := first.Lifecycle.Origin
	revision := identity.Revision{UID: "review", Generation: 1, Digest: artifact.Digest{1}}
	p := value.ContextPreview{ID: fixtureID(9901), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: fixtureID(3), CaptureID: accepted.CaptureID, CaseID: accepted.Group.CaseID, AssessmentID: fixtureID(9902), AssessmentRulesDigest: RecordingSaveGroupAssessmentRulesDigest(), Actor: caller.Principal, ExecutionClass: artifact.ContextAPIExecution, CreatedAt: accepted.CreatedAt, Deadline: accepted.Deadline, SelectionUntil: accepted.CreatedAt.Add(time.Minute), CanonicalScope: bytes.Clone(first.SourceSnapshotManifest.CanonicalScope), ScopeDigest: accepted.ScopeDigest, Storage: value.ContextStorageSelection{StoreID: first.Registration.StoreID, AllocationID: first.Registration.AllocationID, PoolRevision: first.Registration.PoolRevision, AllocationRevision: first.Registration.AllocationRevision, BindingRevision: revision}, Group: &value.RecordingSaveGroupPreview{Executor: ports.policy, PolicyName: "recording", PolicyUID: policy.PolicyUID, ExecutionDigest: policy.PolicyExecutionDigest}}
	p.Target = targets.Request{ClusterID: first.Registration.Location.ClusterID, Namespace: configuration.NamespaceRef{Name: first.Namespace, UID: first.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "api", UID: first.WorkloadUID}}
	p.Intent.Target = targets.WorkloadRequest{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Kind: p.Target.Workload.Kind, Name: p.Target.Workload.Name}
	for _, child := range accepted.Group.Children {
		e := child.Expectation
		q := *e.Snapshot
		digest, err := compiler.SourceAudienceDigest(e.Audience)
		if err != nil {
			t.Fatal(err)
		}
		p.Group.Children = append(p.Group.Children, value.RecordingSaveGroupChild{Reference: value.RecordingReference{SourceID: q.SourceID, Fence: q.Fence, PolicyUID: policy.PolicyUID, PodUID: e.PodUID, ActionID: e.ActionID, BindingDigest: q.SourceBindingDigest, ExecutionDigest: policy.PolicyExecutionDigest}, CaptureID: child.CaptureID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, OccurrenceID: e.OccurrenceID, AssessmentID: fixtureID(9950 + len(p.Group.Children)), Request: q, AudienceDigest: digest, CapabilityRevision: revision, Retention: value.RecordingSaveRetentionReview{PurposeRef: e.PurposeRef, RequestedSeconds: e.RequestedAgeSeconds, MaximumSeconds: e.MaximumAgeSeconds, DeletionBudgetSeconds: e.DeletionBudgetSeconds, PolicyRevision: revision}})
	}
	if !ValidContextPreview(p) {
		t.Fatal("valid grouped history baseline", p.Valid())
	}
	settings, err := HistoryDraftFromPreview(p, accepted)
	if err != nil || settings.RecordingSave == nil || len(settings.RecordingSave.Windows) != 1 || settings.RecordingSave.Windows[0].Before != time.Second || settings.Selection != "recordingSelectionRequired" {
		t.Fatal("parent settings lost or duplicated authored preference", err, settings)
	}
	raw, err := value.CanonicalHistoryParameters(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"SourceID", "SnapshotID", "BindingDigest", "SourceTarget", "Audience", "Grant", "Sharing", p.Group.Children[0].Reference.SourceID, accepted.Group.Children[0].CaptureID} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("repeat retains a stale capability", forbidden)
		}
	}
	p.Group.Children[1].Request.Before = 2 * time.Second
	if _, err = HistoryDraftFromPreview(p, accepted); err == nil {
		t.Fatal("different per-source windows silently became first-child preference")
	}
}
