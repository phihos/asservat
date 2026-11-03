package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// fakeGrants is the C-03 port: it records requests and answers Covering
// from a settable grant and outcome.
type fakeGrants struct {
	requests []authapp.GrantRequestInput
	grant    authorization.Grant
	covering error
}

func (g *fakeGrants) Request(_ context.Context, _ identities.CurrentIdentity, in authapp.GrantRequestInput) (authorization.Grant, bool, error) {
	g.requests = append(g.requests, in)
	g.grant = authorization.Grant{ID: "00000000-0000-4000-8000-0000000009a1", CaptureID: in.CaptureID, ExecutionDigest: in.ExecutionDigest}
	if in.ResultAccess != nil {
		g.grant.ResultAccessDigest = authapp.ResultAccessDigest(in.CaptureID, in.ExecutionDigest, authapp.NormalizeResultAccess(*in.ResultAccess))
	}
	g.covering = authorization.ErrApprovalRequired
	return g.grant, false, nil
}

func (g *fakeGrants) Covering(_ context.Context, _ identities.CurrentIdentity, captureID string, execution artifact.Digest, _ authorization.Target) (authorization.Grant, time.Time, error) {
	if g.grant.ID == "" {
		return authorization.Grant{}, time.Time{}, authorization.ErrApprovalRequired
	}
	if g.grant.CaptureID != captureID || g.grant.ExecutionDigest != execution {
		return g.grant, time.Time{}, authorization.ErrGrantScope
	}
	return g.grant, time.Now().Add(time.Second), g.covering
}

type fixedApprovalSettings struct {
	policy identity.Policy
	err    error
}

func (s fixedApprovalSettings) IdentityPolicy(context.Context, string) (identity.Policy, error) {
	return s.policy, s.err
}

// ADR-249: a raw byte predicate makes the preview need approval; submitting
// it opens exactly one review request, is refused with ApprovalRequired until
// an approved grant covers it, and only then reaches RecorderUnavailable.
// Nothing reaches admission on any path.
func TestSensitiveRecorderPlanNeedsApprovalBeforeAnything(t *testing.T) {
	f := newInvestigationFixture()
	f.svc.Filters = &stubFilters{}
	ctx := context.Background()
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition(planning.ProfileEdit{ActionID: "sample", Field: "packetFilter", Text: "tcp[13] & 2 != 0"})))
	if err != nil || r.Plan.Approval == nil || r.Plan.Approval.Reasons[0].Code != planning.ReasonRawBytePredicate {
		t.Fatal("raw predicate plan does not need approval", err)
	}
	p := r.Preview
	// Without the approval service nothing can cover the plan.
	if _, err := f.request(t, p, "k1"); !errors.Is(err, authorization.ErrApprovalRequired) {
		t.Fatal(err)
	}
	grants := &fakeGrants{}
	f.svc.Grants = grants
	_, err = f.request(t, p, "k1")
	var pending authorization.ApprovalPendingError
	if !errors.As(err, &pending) || len(grants.requests) != 1 {
		t.Fatal("no review request opened", err)
	}
	in := grants.requests[0]
	if in.CaptureID != p.CaptureID || in.ExecutionDigest != p.ScopeDigest || in.PreviewID != p.ID || in.Actor != f.actor || in.DataClass != "extract" || len(in.Review.Actions) != 1 || in.Review.Actions[0].Filter != "tcp[13] & 2 != 0" || in.Review.ObservationLimits == nil || in.Lifetime != authorization.GrantDefaultLifetime {
		t.Fatalf("review request %+v", in)
	}
	// A retry while pending names the same request and opens no other.
	if _, err = f.request(t, p, "k2"); !errors.As(err, &pending) || pending.GrantID != grants.grant.ID || len(grants.requests) != 1 {
		t.Fatal("pending retry", err)
	}
	// A different result-access instruction needs a fresh preview.
	access := &authorization.ResultAccess{ActionIDs: []string{r.Plan.Actions[0].ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 1 << 20, MaxOperations: 4, NotAfter: f.now.Add(time.Hour)}
	if _, err = f.svc.RequestWithResultAccess(ctx, f.source(t, ctx), p.ID, "k3", access); !errors.Is(err, value.ErrConflict) {
		t.Fatal("result access replaced on a pending request", err)
	}
	// Denied, revoked and expired grants stay refusals.
	for _, final := range []error{authorization.ErrGrantDenied, authorization.ErrGrantRevoked, authorization.ErrGrantExpired, authorization.ErrGrantPrincipal} {
		grants.covering = final
		if _, err = f.request(t, p, "k4"); !errors.Is(err, final) {
			t.Fatal(final, err)
		}
	}
	// Covered: the next blocker is the absent recorder.
	grants.covering = nil
	if _, err = f.request(t, p, "k5"); !errors.Is(err, value.ErrRecorderUnavailable) {
		t.Fatal(err)
	}
	if f.admissions.Load() != 0 || len(f.accepted) != 0 {
		t.Fatal("a sensitive plan reached admission")
	}
	// An expired preview cannot open a new request.
	grants.grant, grants.requests = authorization.Grant{}, nil
	f.now = p.Deadline.Add(time.Second)
	if _, err = f.request(t, p, "k6"); !errors.Is(err, value.ErrPreviewExpired) || len(grants.requests) != 0 {
		t.Fatal("expired preview opened a request", err)
	}
}

func TestRecorderApprovalSettingsAndResultAccess(t *testing.T) {
	f := newInvestigationFixture()
	ctx := context.Background()
	// The installation's switch makes a metadata recording need approval.
	policy := identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}
	f.svc.Approvals = fixedApprovalSettings{policy: policy}
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
	if err != nil || r.Plan.Approval == nil || r.Plan.Approval.Reasons[0].Code != planning.ReasonRecordingApproval || r.Plan.Approval.ObservationLimits != nil {
		t.Fatal("installation requirement not applied", err)
	}
	// A failing settings read refuses the preview rather than skipping it.
	f.svc.Approvals = fixedApprovalSettings{err: identity.ErrUnavailable}
	if _, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition())); err == nil {
		t.Fatal("unavailable approval settings ignored")
	}
	// Without the switch the metadata plan needs no approval, and a
	// result-access instruction on it is invalid.
	policy.RequireRecordingApproval = false
	f.svc.Approvals = fixedApprovalSettings{policy: policy}
	f.svc.Grants = &fakeGrants{}
	r, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
	if err != nil || r.Plan.Approval != nil {
		t.Fatal(err)
	}
	access := &authorization.ResultAccess{ActionIDs: []string{r.Plan.Actions[0].ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 1, MaxOperations: 1, NotAfter: f.now.Add(time.Hour)}
	if _, err = f.svc.RequestWithResultAccess(ctx, f.source(t, ctx), r.Preview.ID, "k", access); !errors.Is(err, value.ErrInvalid) {
		t.Fatal("result access on a plan without review", err)
	}
	if _, err = f.request(t, r.Preview, "k"); !errors.Is(err, value.ErrRecorderUnavailable) {
		t.Fatal(err)
	}
}

func TestRecordingApprovalSettingsChangeRequiresFreshReview(t *testing.T) {
	for _, original := range []bool{false, true} {
		t.Run(map[bool]string{false: "approval-now-required", true: "approval-no-longer-required"}[original], func(t *testing.T) {
			f := newInvestigationFixture()
			ctx := context.Background()
			policy := identity.Policy{Revision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{1}}, Issuer: f.actor.Issuer, ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: original}
			f.svc.Approvals = fixedApprovalSettings{policy: policy}
			preview, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
			if err != nil {
				t.Fatal(err)
			}
			policy.RequireRecordingApproval = !original
			f.svc.Approvals = fixedApprovalSettings{policy: policy}
			if _, err = f.request(t, preview.Preview, "changed-settings"); !errors.Is(err, value.ErrChanged) || f.admissions.Load() != 0 {
				t.Fatal("changed administrator requirement did not require new review", err)
			}
		})
	}
}

func TestRecorderSubmissionRejectsAnotherIssuersApprovalSettings(t *testing.T) {
	f := newInvestigationFixture()
	ctx := context.Background()
	p, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition()))
	if err != nil {
		t.Fatal(err)
	}
	// A complete, fresh policy for another issuer cannot supply this issuer's
	// administrator settings, even if its switch agrees with the frozen plan.
	policy := identity.Policy{Revision: identity.Revision{UID: "other-policy", Generation: 1, Digest: [32]byte{1}}, Issuer: "https://other.example.invalid", ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), Clients: []identity.Client{{ID: "console", Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"dev-team"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute}
	if policy.Validate(f.now) != nil {
		t.Fatal("fixture policy is invalid")
	}
	f.svc.Approvals = fixedApprovalSettings{policy: policy}
	if _, err = f.request(t, p.Preview, "other-issuer"); !errors.Is(err, value.ErrUnavailable) || f.admissions.Load() != 0 {
		t.Fatal("foreign settings supplied approval authority", err)
	}
}

// Only the mechanism pins are synthetic; the catalog, planner, canonical scope
// and review request producer use their normal application path.
type approvalArgumentCompiler struct{ stubFilters }

func (approvalArgumentCompiler) CompileArguments(_ []string, buffers bool, maximum int64) (artifact.RecordingArguments, error) {
	return artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest(collector.ArgumentObservationAccountingRule()), MaxProbeBytes: 512, MaxBytesPerEvent: maximum, MaxBytesPerSecond: planning.SensitiveMaxBytesPerSecond, CaptureBuffers: buffers}, nil
}

func TestArgumentRecorderApprovalRetainsCanonicalEventCeiling(t *testing.T) {
	f := newInvestigationFixture()
	retained := &retainedRecording{investigationFixture: f}
	f.target.NodeUID, f.target.NodeBootID, f.target.Pin.NodeName = "", "", ""
	f.target.ExecutionClass, f.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	f.svc.Previews, f.svc.Admission, f.svc.Recorders = retained, retained, bothRecorders{availableRecording{f}}
	f.svc.Filters = &approvalArgumentCompiler{}
	raw, err := os.ReadFile("../planning/profiles/syscall-activity-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "argument-review"
	a := doc["definition"].(map[string]any)["recipe"].(map[string]any)["actions"].([]any)[0].(map[string]any)
	a["impact"], a["executionMode"] = "sensitiveRead", "onTrigger"
	params := a["parameters"].(map[string]any)
	params["mode"], params["before"], params["after"] = "arguments", "0s", "3s"
	params["syscalls"] = map[string]any{"mode": "include", "names": []string{"read", "write"}}
	params["arguments"] = map[string]any{"maxBytesPerEvent": 128, "captureBuffers": false}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	ref := planning.ProfileRef{Catalog: "namespace", Name: "argument-review", Version: "v1"}
	f.svc.Profiles = &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceClusterID: fixtureID(4), SourceNamespaceUID: "ns", SourceUID: "argument-profile", Document: raw, Enabled: true}}}
	composition := &planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "calls", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	preview, err := f.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(composition))
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Recordable {
		t.Fatal("argument preview not recordable")
	}
	if preview.Preview.AssessmentRulesDigest != preview.Assessment.RulesDigest {
		t.Error("persisted preview lost argument assessment rule identity")
	}
	_, canonical, err := compiler.RecorderScopeSummary(preview.Preview.CanonicalScope)
	if err != nil || canonical == nil || canonical.ObservationLimits == nil || canonical.ObservationLimits.MaxObservedEvents != 40000 {
		t.Fatal("canonical argument event ceiling", canonical, err)
	}
	grants := &fakeGrants{}
	f.svc.Grants = grants
	access := &authorization.ResultAccess{ActionIDs: []string{preview.Plan.Actions[0].ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 16 << 20, MaxOperations: 1, NotAfter: f.now.Add(time.Hour)}
	_, err = f.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), preview.Preview.ID, "argument-review", access)
	if !errors.Is(err, authorization.ErrApprovalRequired) || len(grants.requests) != 1 {
		t.Fatal("review request", err)
	}
	got := grants.requests[0].Review.ObservationLimits
	if got == nil || got.MaxObservedEvents != canonical.ObservationLimits.MaxObservedEvents {
		t.Fatalf("GrantReview lost canonical event ceiling: got %+v, want %d", got, canonical.ObservationLimits.MaxObservedEvents)
	}
	if f.admissions.Load() != 0 {
		t.Fatal("review request acquired evidence")
	}
	f.now = preview.Preview.Deadline.Add(time.Minute)
	grants.grant.ExpiresAt, grants.covering = access.NotAfter, nil
	if _, err = f.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), preview.Preview.ID, "argument-review", access); !errors.Is(err, reachedRecordingAdmission) || len(retained.seen) != 1 {
		t.Fatal("approved argument assessment changed before admission", err)
	}
	stored := f.previews[preview.Preview.ID]
	if stored.AssessmentRulesDigest != preview.Assessment.RulesDigest || !stored.Deadline.Equal(preview.Preview.Deadline) {
		t.Fatal("original preview changed")
	}
	stored.AssessmentRulesDigest = compiler.RecorderAssessmentRulesDigest()
	f.previews[stored.ID] = stored
	if _, err = f.svc.RequestWithResultAccess(t.Context(), f.source(t, t.Context()), stored.ID, "wrong-rules", access); err == nil || len(retained.seen) != 1 {
		t.Fatal("generic rules accepted argument scope", err)
	}
}
