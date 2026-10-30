package capture

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// Persisted control size only: source target/audience/policy payloads stay in
// their immutable protected source/current-policy rows and are not duplicated.
func recordingGroupSizePreview(t *testing.T, n int) value.ContextPreview {
	t.Helper()
	x, _, _, _ := newRecordingInventoryFixture(t, n)
	f := x.f
	now := f.now
	a := x.policy.Accepted.Authority
	actor := f.actor
	actor.Issuer = "https://identity.example.invalid/" + strings.Repeat("a", 2048-len("https://identity.example.invalid/"))
	actor.Subject = strings.Repeat("s", 256)
	actor.ClientID = strings.Repeat("c", 128)
	a.Creator = actor
	a.PolicyUID = strings.Repeat("p", 64)
	a.Executor = authorization.PolicyPrincipal(a.InstallationID, a.PolicyUID)
	a.NamespaceUID, a.WorkloadUID = strings.Repeat("n", 64), strings.Repeat("w", 64)
	p := value.ContextPreview{Group: &value.RecordingSaveGroupPreview{Executor: a.Executor, PolicyName: strings.Repeat("p", 63), PolicyUID: a.PolicyUID, ExecutionDigest: a.ScopeDigest}, ID: f.svc.NewID(), RootID: f.svc.RootID, InstallationID: f.svc.InstallationID, IssuerEpoch: f.epoch, CaptureID: f.svc.NewID(), CaseID: f.svc.NewID(), AssessmentID: f.svc.NewID(), AssessmentRulesDigest: compiler.SourceSnapshotAssessmentRulesDigest(), Actor: actor, Storage: f.store.Selection, CreatedAt: now, Deadline: now.Add(15 * time.Second), SelectionUntil: now.Add(15 * time.Second)}
	p.Intent.Target = targets.WorkloadRequest{ClusterID: a.ClusterID, Namespace: strings.Repeat("n", 63), Kind: "Deployment", Name: strings.Repeat("w", 63)}
	p.Target = x.rows[0].Source.Target.Request
	p.Target.Namespace.Name, p.Target.Namespace.UID = p.Intent.Target.Namespace, a.NamespaceUID
	p.Target.Workload.Name, p.Target.Workload.UID = p.Intent.Target.Name, a.WorkloadUID
	p.Target.PodUID, p.Target.PodName = "", ""
	var sources []compiler.RecordingSaveScopeSource
	for _, row := range x.rows {
		original := *row.Source.Target
		original.Request.Namespace = p.Target.Namespace
		original.Request.Workload = p.Target.Workload
		original.Request.PodName = strings.Repeat("p", 253)
		original.Request.PodUID = strings.Repeat("u", 60) + original.SourceID[len(original.SourceID)-4:]
		original.Pin.Name, original.Pin.UID, original.Pin.Namespace, original.Pin.NamespaceUID = original.Request.PodName, original.Request.PodUID, p.Target.Namespace.Name, p.Target.Namespace.UID
		ref := value.RecordingReference{SourceID: original.SourceID, Fence: original.Fence, PolicyUID: a.PolicyUID, PodUID: original.Request.PodUID, ActionID: strings.Repeat("a", 63), BindingDigest: artifact.Digest(original.BindingDigest), ExecutionDigest: a.ScopeDigest}
		q := artifact.SourceSnapshotRequest{SourceID: ref.SourceID, Fence: ref.Fence, SnapshotID: f.svc.NewID(), SourceBindingDigest: ref.BindingDigest, SourceStartedAt: now.Add(-time.Hour), SourceHardUntil: now.Add(time.Hour), T0: now, IssuedAt: now, StartBy: now.Add(5 * time.Second), ProcessingUntil: p.Deadline, Before: time.Hour, MaxBytes: artifact.RecordingNativeLimit}
		revision := identity.Revision{UID: strings.Repeat("r", 64), Generation: 2147483647, Digest: artifact.Digest{3}}
		p.Group.Children = append(p.Group.Children, value.RecordingSaveGroupChild{Reference: ref, CaptureID: f.svc.NewID(), ArtifactID: f.svc.NewID(), AttemptID: f.svc.NewID(), OccurrenceID: f.svc.NewID(), AssessmentID: f.svc.NewID(), Request: q, AudienceDigest: artifact.Digest{2}, CapabilityRevision: revision, Retention: value.RecordingSaveRetentionReview{PurposeRef: strings.Repeat("p", 128), RequestedSeconds: 315360000, MaximumSeconds: 315360000, DeletionBudgetSeconds: 86400, PolicyRevision: revision}})
		sources = append(sources, compiler.RecordingSaveScopeSource{PolicyUID: a.PolicyUID, ExecutionDigest: a.ScopeDigest, Original: original, ActionID: ref.ActionID, Kind: "packetCapture", DefinitionDigest: artifact.Digest{4}, AudienceDigest: artifact.Digest{2}, ApprovedBefore: time.Hour, Before: time.Hour, MaxBytes: artifact.RecordingNativeLimit, CeilingDigest: artifact.Digest{3}, RetentionDigest: artifact.Digest{3}})
	}
	var err error
	p.CanonicalScope, p.ScopeDigest, err = compiler.CompileRecordingSaveScope(compiler.RecordingSaveScopeInput{CaptureID: p.CaptureID, Requester: actor, Authority: a, Sources: sources, IncidentPodLimit: n, FinalizeTimeout: time.Hour, CeilingDigest: artifact.Digest{3}, RetentionDigest: artifact.Digest{3}}, now)
	if err != nil {
		t.Fatal("actual grouped canonical scope", err)
	}
	return p
}

func TestRecordingSaveGroupMaximumReviewFitsExistingPreviewJournal(t *testing.T) {
	for _, n := range []int{2, 16} {
		p := recordingGroupSizePreview(t, n)
		if !ValidContextPreview(p) {
			t.Fatal("structurally valid bounded group preview required", n, p.Valid())
		}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > value.MaxContextPreviewBytes {
			t.Fatal("group exceeded existing128KiB journal", n, len(raw))
		}
		t.Logf("group_sources=%d max_review_bytes=%d canonical_scope_bytes=%d cap=%d; fullaudience/policy/label payloads notduplicated", n, len(raw), len(p.CanonicalScope), value.MaxContextPreviewBytes)
	}
}
