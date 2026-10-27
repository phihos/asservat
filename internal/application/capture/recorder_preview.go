package capture

import (
	"context"
	"errors"
	"slices"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
)

// RecorderPreviewResult is a reviewed packet/syscall plan (ADR-243). Only
// Preview is persisted, so request_capture can refuse it with the same
// RecorderUnavailable blocker before acceptance; nothing is reserved.
type RecorderPreviewResult struct {
	Preview    value.ContextPreview
	Plan       planning.RecorderPlan
	Assessment planning.RecorderAssessment
	ValidUntil time.Time // Original metadata-delivery authority; never persisted.
	// Recordable marks an acceptable plan for an available node recorder
	// (ADR-248): request_capture can accept it.
	Recordable bool
}

// PreviewComposition compiles a one-component builtin capture profile
// composition for a currently authorized workload. It reads identity,
// recovery, the target, collection eligibility and retention exactly as a
// pod-status preview does, but no collector capability, storage binding or
// processing coverage: no recorder exists to use them. Authored composition
// errors are reported only after eligibility, so they disclose nothing about
// an unauthorized target. The libpcap compiler runs on the hub (S2).
func (s ContextInvestigation) PreviewComposition(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent) (result RecorderPreviewResult, failure error) {
	defer func() { s.reportPreviewFailure(failure) }()
	var zero RecorderPreviewResult
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return zero, previewFailure("configuration", value.ErrUnavailable)
	}
	if intent.Composition == nil || !intent.Valid() {
		return zero, previewFailure("composition/intent", value.ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	created := s.Now().UTC().Truncate(time.Microsecond)
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, previewFailure("identity", value.ErrDenied)
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return zero, previewFailure("recovery", err)
	}
	mark := time.Now()
	target, err := s.Targets.ResolveWorkload(ctx, intent.Target)
	auditapp.MarkStep(ctx, "p-target", mark)
	if err != nil {
		return zero, previewFailure("target", err)
	}
	if !target.Valid(s.Now()) {
		return zero, previewFailure("facts/target", value.ErrChanged)
	}
	if s.packetRecorderAvailable(ctx, intent, target) {
		r, err := s.previewRecording(ctx, source, intent, i, recovery, target, created)
		if !errors.Is(err, errRecordingNotAcceptable) {
			return r, err
		}
	}
	t := target.Target()
	eligibility := s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	if !eligibility.Eligible || eligibility.Target != t || eligibility.Principal != i.Principal || eligibility.VerifiedIdentity.Principal != i.Principal || !eligibility.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(eligibility.ValidUntil) {
		return zero, previewFailure(previewEligibilityFailure(eligibility.Reason), value.ErrDenied)
	}
	// Authored errors only after current eligibility on the target.
	evidence, err := compiler.RecorderEvidenceType(*intent.Composition)
	if err != nil {
		return zero, previewFailure("composition", err)
	}
	r, err := s.Retention.Resolve(ctx, privacy.Input{Target: t, PrivacyClass: "potentialPersonalData", EvidenceType: evidence, RequestedSeconds: intent.RequestedSeconds, AnchorAt: created})
	if err != nil {
		return zero, previewFailure("facts/retention/"+retentionFailure(err), err)
	}
	current := func(now time.Time) bool {
		p := r.Proof
		return target.Valid(now) && p.Valid(now) && p.Matches(s.RootID, t.ClusterID, t.NamespaceUID, t.WorkloadUID, t.PodUID) && p.Policy == r.PolicyRevision && !r.ValidUntil.After(p.ValidUntil) && now.Before(r.ValidUntil) && now.Before(eligibility.ValidUntil) && eligibility.VerifiedIdentity.Valid(now) && recovery.Valid(now)
	}
	if !current(s.Now()) || ctx.Err() != nil {
		return zero, previewFailure("facts/current", value.ErrChanged)
	}
	p := value.ContextPreview{ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Retention: retentionReview(r), Audience: slices.Clone(eligibility.DefaultAudience), CreatedAt: created, Deadline: created.Add(s.Lifetime)}
	p.Intent.Composition = intent.Composition.Clone()
	p.ExecutionClass = target.ExecutionClass
	p.AssessmentID, p.AssessmentRulesDigest = s.NewID(), compiler.RecorderAssessmentRulesDigest()
	required, err := s.requireRecordingApproval(ctx, i)
	if err != nil {
		return zero, previewFailure("approvals", err)
	}
	mark = time.Now()
	plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: p.CaptureID, Executor: p.Actor, Target: target, Composition: *intent.Composition, Retention: r, Deadline: p.Deadline, RequireApproval: required}, s.Filters, s.Now())
	auditapp.MarkStep(ctx, "p-compile", mark)
	if err != nil {
		return zero, previewFailure("compile", err)
	}
	p.CanonicalScope, p.ScopeDigest = slices.Clone(plan.CanonicalScope), plan.ScopeDigest
	assessment, err := compiler.AssessRecorder(plan, p.AssessmentID, s.Now())
	if err != nil {
		return zero, previewFailure("assessment", err)
	}
	if !ValidContextPreview(p) || !p.Current(s.Now()) {
		return zero, previewFailure("blueprint", value.ErrInvalid)
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !current(s.Now()) {
		return zero, previewFailure("before-store/current", value.ErrChanged)
	}
	mark = time.Now()
	err = s.Previews.CreateContextPreview(ctx, p.Clone())
	auditapp.MarkStep(ctx, "p-store", mark)
	if err != nil {
		return zero, previewFailure("store", err)
	}
	final := s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	if !final.Eligible || final.Target != t || final.Principal != i.Principal || !final.VerifiedIdentity.Valid(s.Now()) || !i.Valid(s.Now()) || !slices.Equal(final.DefaultAudience, p.Audience) || !s.Now().Before(final.ValidUntil) || !current(s.Now()) || ctx.Err() != nil || s.Now().Before(created) {
		return zero, previewFailure("after-store/current", value.ErrChanged)
	}
	until := identity.Earlier(i.ValidUntil, recovery.FreshUntil)
	for _, bound := range []time.Time{final.ValidUntil, final.VerifiedIdentity.ValidUntil, eligibility.ValidUntil, eligibility.VerifiedIdentity.ValidUntil, assessment.ValidUntil, plan.ValidUntil} {
		until = identity.Earlier(until, bound)
	}
	if !s.Now().Before(until) || ctx.Err() != nil {
		return zero, previewFailure("response/current", value.ErrUnavailable)
	}
	return RecorderPreviewResult{Preview: p.Clone(), Plan: plan, Assessment: assessment, ValidUntil: until}, nil
}
