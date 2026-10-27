package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type availableRecording struct{ fixture *investigationFixture }

func (a availableRecording) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return a.fixture.svc.Targets.ResolvePod(ctx, r)
}
func (availableRecording) PacketRecorder(context.Context, targets.PodResolution) error { return nil }

// SQL separately qualifies retained immutable reads and current-grant locking.
// This port deliberately returns the original expired blueprint to the service.
type retainedRecording struct {
	*investigationFixture
	seen []value.Admission
}

func (f *retainedRecording) ReadContextPreview(_ context.Context, root, id string, actor identity.Principal) (value.ContextPreview, error) {
	p, ok := f.previews[id]
	if !ok || p.RootID != root || p.Actor != actor {
		return value.ContextPreview{}, value.ErrDenied
	}
	return p.Clone(), nil
}

var reachedRecordingAdmission = errors.New("test reached recording admission")

func (f *retainedRecording) AdmitReviewedContext(_ context.Context, _ string, a value.Admission) (value.Accepted, error) {
	f.seen = append(f.seen, a)
	return value.Accepted{}, reachedRecordingAdmission
}

func TestApprovedRecordingStartsAfterPreviewExpiryWithOriginalPlan(t *testing.T) {
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableRecording{base}
	policy := identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}
	base.svc.ReportPreviewFailure = func(stage string) { t.Log("stage", stage) }
	base.svc.Approvals = fixedApprovalSettings{policy: policy}
	grants := &fakeGrants{}
	base.svc.Grants = grants
	ctx := context.Background()
	preview, err := base.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
	if err != nil || !preview.Recordable || preview.Plan.Approval == nil {
		t.Fatal("preview", err)
	}
	p := preview.Preview
	if _, err = f.request(t, p, "review"); !errors.Is(err, authorization.ErrApprovalRequired) || len(grants.requests) != 1 {
		t.Fatal("review", err)
	}
	f.now = p.Deadline.Add(time.Minute)
	policy.ObservedAt, policy.FreshUntil = f.now, f.now.Add(30*time.Second)
	base.svc.Approvals = fixedApprovalSettings{policy: policy}
	// No new approval may be opened after expiry.
	old := grants.grant
	grants.grant = authorization.Grant{}
	if _, err = f.request(t, p, "late-review"); !errors.Is(err, value.ErrPreviewExpired) || len(grants.requests) != 1 {
		t.Fatal("opened a late review", err)
	}
	grants.grant = old
	grants.grant.ExpiresAt = f.now.Add(90 * time.Second)
	grants.covering = nil
	if _, err = f.request(t, p, "start"); !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
		t.Fatal("approved start", err)
	}
	got := f.seen[0]
	if got.Plan.Input.CaptureID != p.CaptureID || got.CaseID != p.CaseID || got.OccurrenceID != p.OccurrenceID || got.Plan.Input.Target.Request != p.Target || got.Plan.Input.Target.Pin != p.Pin || got.Plan.ScopeDigest != p.ScopeDigest || got.Registration.Location.ArtifactID != p.ArtifactID || got.Registration.Location.AttemptID != p.AttemptID || !got.Plan.Input.Deadline.Equal(grants.grant.ExpiresAt) || !got.Registration.AnchorAt.Equal(f.now) || !compiler.VerifyContextPlan(got.Plan, f.now) {
		t.Fatal("approval changed plan/identity or consumed retention")
	}
	if stored := f.previews[p.ID]; !stored.Deadline.Equal(p.Deadline) || !stored.CreatedAt.Equal(p.CreatedAt) {
		t.Fatal("original preview was renewed")
	}
	for _, refusal := range []error{authorization.ErrGrantDenied, authorization.ErrGrantRevoked, authorization.ErrGrantExpired} {
		grants.covering = refusal
		if _, err = f.request(t, p, "refused"); !errors.Is(err, refusal) || len(f.seen) != 1 {
			t.Fatal("grant refusal", refusal, err)
		}
	}
	grants.covering = nil
	base.missing = true
	if _, err = f.request(t, p, "missing"); err == nil || len(f.seen) != 1 {
		t.Fatal("missing original Pod reached admission", err)
	}
	base.missing = false
	base.denied = true
	if _, err = base.svc.Request(ctx, fixtureIdentityResolverHandle{base}, p.ID, "denied"); err == nil || len(f.seen) != 1 {
		t.Fatal("revoked requester reached admission", err)
	}
}

var _ ContextPreviewStore = (*retainedRecording)(nil)
var _ identities.CurrentIdentity = fixtureIdentityResolverHandle{}
