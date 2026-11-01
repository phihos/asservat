package capture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// CompositionGroupAdmissions admits all children of one reviewed manual
// composition group atomically (ADR-276).
type CompositionGroupAdmissions interface {
	AdmitRecordingCompositionGroup(context.Context, value.RecordingSaveGroupAdmission) (value.Accepted, error)
}

// compositionChild is child n of a composition group as the single manual
// recording preview it is compiled, assessed and admitted like.
func compositionChild(p value.ContextPreview, n int) value.ContextPreview {
	c := p.CompositionGroup.Children[n]
	q := p.Clone()
	q.CompositionGroup = nil
	q.CaptureID, q.ArtifactID, q.AttemptID, q.OccurrenceID, q.AssessmentID = c.CaptureID, c.ArtifactID, c.AttemptID, c.OccurrenceID, c.AssessmentID
	q.Intent.Composition = c.Composition.Clone()
	q.Retention = c.Retention
	q.Retention.Policies = slices.Clone(c.Retention.Policies)
	q.CanonicalScope, q.ScopeDigest = slices.Clone(c.CanonicalScope), c.ScopeDigest
	return q
}

// childRetention re-resolves only retention for a sibling's evidence type;
// eligibility, capability and storage are the group's one observation.
func (s ContextInvestigation) childRetention(ctx context.Context, f contextFacts, c planning.ProfileComposition, requested int64, anchor time.Time) (contextFacts, error) {
	evidence, err := compiler.RecorderEvidenceType(c)
	if err != nil {
		return f, previewFailure("facts/composition", err)
	}
	f.retention, err = s.Retention.Resolve(ctx, privacy.Input{Target: f.target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidence, RequestedSeconds: requested, AnchorAt: anchor})
	if err != nil {
		return f, previewFailure("facts/retention/"+retentionFailure(err), err)
	}
	if !s.factsCurrent(f, s.Now()) {
		return f, previewFailure("facts/current", value.ErrChanged)
	}
	return f, nil
}

// previewCompositionGroup is PreviewComposition for a manual packet +
// syscall composition (ADR-276): one child single recording per component,
// all on the target's node recorders, under one parent review.
func (s ContextInvestigation) previewCompositionGroup(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent, i identity.Identity, recovery artifact.RecoveryProof, target targets.PodResolution, created time.Time) (RecorderPreviewResult, error) {
	var zero RecorderPreviewResult
	if _, _, policy := authorization.PolicyExecutor(i.Principal); policy || intent.RepeatedFrom != nil {
		return zero, previewFailure("composition", value.ErrInvalid)
	}
	t := target.Target()
	eligibility := s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	if !eligibility.Eligible || eligibility.Target != t || eligibility.Principal != i.Principal || !eligibility.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(eligibility.ValidUntil) {
		return zero, previewFailure(previewEligibilityFailure(eligibility.Reason), value.ErrDenied)
	}
	// Authored errors only after current eligibility on the target.
	parts, err := compiler.SplitComposition(*intent.Composition, s.Filters)
	if err != nil {
		return zero, previewFailure("composition", err)
	}
	if len(parts) < 2 {
		return zero, previewFailure("composition", value.ErrInvalid)
	}
	for _, c := range parts {
		one := intent
		one.Composition = &c
		available, err := s.packetRecorderAvailable(ctx, one, target)
		if err != nil {
			return zero, previewFailure("recorder", err)
		}
		if !available {
			return zero, value.ErrRecorderUnavailable
		}
	}
	first := intent
	first.Composition = &parts[0]
	f, err := s.facts(ctx, source, i.Principal, first, target, created, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	if err != nil {
		return zero, previewFailure("facts", err)
	}
	required, err := s.requireRecordingApproval(ctx, source, i.Principal)
	if err != nil {
		return zero, previewFailure("approvals", err)
	}
	p := value.ContextPreview{ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), AssessmentID: s.NewID(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Storage: f.storage.Selection, Retention: retentionReview(f.retention), Audience: slices.Clone(f.eligibility.DefaultAudience), CreatedAt: created, Deadline: created.Add(s.Lifetime), CompositionGroup: &value.CompositionGroupPreview{}}
	p.Intent.Composition = intent.Composition.Clone()
	p.ExecutionClass = target.ExecutionClass
	p.AssessmentRulesDigest = compiler.RecorderAssessmentRulesDigest()
	plans := make([]planning.RecorderPlan, len(parts))
	assessments := make([]planning.RecorderAssessment, len(parts))
	facts := make([]contextFacts, len(parts))
	for n, c := range parts {
		if facts[n], err = s.childRetention(ctx, f, c, intent.RequestedSeconds, created); err != nil {
			return zero, err
		}
		child := value.CompositionGroupChild{CaptureID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), OccurrenceID: s.NewID(), AssessmentID: s.NewID(), Composition: *c.Clone(), Retention: retentionReview(facts[n].retention)}
		plans[n], err = compiler.CompileRecorder(planning.RecorderInput{CaptureID: child.CaptureID, Executor: p.Actor, Target: target, Composition: c, Retention: facts[n].retention, Deadline: p.Deadline, NodeRecorder: true, RequireApproval: required}, s.Filters, s.Now())
		if err != nil {
			return zero, previewFailure("compile", err)
		}
		if len(plans[n].Actions) != 1 || !compiler.AcceptableRecorder(plans[n]).Acceptable() {
			return zero, errRecordingNotAcceptable
		}
		child.ActionID, child.CanonicalScope, child.ScopeDigest = plans[n].Actions[0].ID, slices.Clone(plans[n].CanonicalScope), plans[n].ScopeDigest
		if assessments[n], err = compiler.AssessRecorder(plans[n], child.AssessmentID, s.Now()); err != nil {
			return zero, previewFailure("assessment", err)
		}
		p.CompositionGroup.Children = append(p.CompositionGroup.Children, child)
	}
	if p.CanonicalScope, p.ScopeDigest, err = compiler.CompileRecorderGroup(p.CaptureID, plans); err != nil {
		return zero, previewFailure("compile/group", err)
	}
	display, assessment, err := compiler.RecorderGroupDisplay(p.CanonicalScope, p.ScopeDigest, p.AssessmentID, plans, assessments)
	if err != nil {
		return zero, previewFailure("assessment", err)
	}
	coverageUntil := time.Time{}
	for n := range parts {
		cp := compositionChild(p, n)
		coverage, err := s.processingCoverage(ctx, cp, facts[n], recovery, i.ValidUntil)
		if err != nil {
			return zero, previewFailure("processing", err)
		}
		if coverageUntil.IsZero() || coverage.FreshUntil.Before(coverageUntil) {
			coverageUntil = coverage.FreshUntil
		}
		// The accepted context plan must reproduce the reviewed scope exactly.
		accepted, err := s.recordingPlan(ctx, cp, facts[n])
		if err != nil || accepted.ScopeDigest != plans[n].ScopeDigest {
			return zero, previewFailure("compile/accepted", value.ErrInvalid)
		}
	}
	if !ValidContextPreview(p) || !p.Current(s.Now()) {
		return zero, previewFailure("blueprint", value.ErrInvalid)
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !s.factsCurrent(f, s.Now()) || !s.Now().Before(coverageUntil) || !recovery.Valid(s.Now()) {
		return zero, previewFailure("before-store/current", value.ErrChanged)
	}
	if err = s.Previews.CreateContextPreview(ctx, p.Clone()); err != nil {
		return zero, previewFailure("store", err)
	}
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	if !current.Eligible || current.Target != t || current.Principal != i.Principal || !current.VerifiedIdentity.Valid(s.Now()) || !i.Valid(s.Now()) || !slices.Equal(current.DefaultAudience, p.Audience) || !s.Now().Before(current.ValidUntil) || !s.factsCurrent(f, s.Now()) || !s.Now().Before(coverageUntil) || !recovery.Valid(s.Now()) || ctx.Err() != nil {
		return zero, previewFailure("after-store/current", value.ErrChanged)
	}
	until := identity.Earlier(i.ValidUntil, recovery.FreshUntil)
	for _, bound := range []time.Time{current.ValidUntil, current.VerifiedIdentity.ValidUntil, f.eligibility.ValidUntil, assessment.ValidUntil, display.ValidUntil, f.storage.Binding.FreshUntil, coverageUntil} {
		until = identity.Earlier(until, bound)
	}
	if !s.Now().Before(until) || ctx.Err() != nil {
		return zero, previewFailure("response/current", value.ErrUnavailable)
	}
	return RecorderPreviewResult{CollectorImageDigest: f.capability.CollectorImageDigest, ProjectionDigest: f.capability.ProjectionDigest, Preview: p.Clone(), Plan: display, Assessment: assessment, ValidUntil: until, Recordable: true}, nil
}

// requestCompositionGroup is Request for a reviewed composition group: one
// approval gate for the parent, both node recorders resolved for the same
// Pod, and one atomic admission of every child (ADR-276).
func (s ContextInvestigation) requestCompositionGroup(ctx context.Context, source identities.CurrentIdentity, p value.ContextPreview, key string, i identity.Identity, recovery artifact.RecoveryProof) (value.Accepted, error) {
	var zero value.Accepted
	admit, ok := s.Admission.(CompositionGroupAdmissions)
	if !ok || s.Recorders == nil {
		return zero, value.ErrRecorderUnavailable
	}
	if _, _, policy := authorization.PolicyExecutor(p.Actor); policy {
		return zero, value.ErrInvalid
	}
	children := p.CompositionGroup.Children
	for n := range children {
		if children[n].Composition.Resolved == nil {
			// A stored preview carries no catalog documents (REQ-CPR-001).
			c, err := s.withCatalogProfiles(ctx, &children[n].Composition, targets.PodResolution{Request: p.Target})
			if err != nil {
				return zero, previewFailure("profiles", err)
			}
			children[n].Composition = *c
		}
	}
	if p.IssuerEpoch != recovery.IssuerEpoch || p.AssessmentRulesDigest != compiler.RecorderAssessmentRulesDigest() {
		return zero, s.requestChanged("epoch")
	}
	grant, err := s.recorderRequest(ctx, source, p, key, nil)
	if err != nil {
		return zero, err
	}
	if grant.ID != "" {
		// ADR-252 per child: only approved-timing scopes get an acceptance
		// deadline, never beyond the one parent grant.
		for _, c := range children {
			if !compiler.RecorderApprovedAcceptance(c.CanonicalScope) {
				return zero, s.requestChanged("approval/timing")
			}
		}
		p.CreatedAt = s.Now().UTC().Truncate(time.Microsecond)
		p.Deadline = identity.Earlier(p.CreatedAt.Add(s.Lifetime), grant.ExpiresAt)
	}
	if p.Storage == (value.ContextStorageSelection{}) {
		return zero, value.ErrRecorderUnavailable
	}
	if !p.Current(s.Now()) {
		return zero, value.ErrPreviewExpired
	}
	ctx, end := context.WithDeadline(ctx, p.Deadline)
	defer end()
	var target targets.PodResolution
	for n := range children {
		cp := compositionChild(p, n)
		var resolved targets.PodResolution
		if syscallRecorderInput(cp.Intent) {
			syscalls, ok := s.Recorders.(SyscallRecorders)
			if !ok {
				return zero, value.ErrRecorderUnavailable
			}
			resolved, err = syscalls.ResolveSyscallRecorder(ctx, p.Target)
		} else {
			resolved, err = s.Recorders.ResolvePacketRecorder(ctx, p.Target)
		}
		if errors.Is(err, targets.ErrUnsupported) {
			return zero, value.ErrRecorderUnavailable
		}
		if err != nil {
			return zero, previewFailure("target/"+targetFailureClass(err), err)
		}
		if resolved.Request != p.Target || resolved.Pin != p.Pin || resolved.ExecutionClass != p.ExecutionClass {
			return zero, s.requestChanged("target")
		}
		if n == 0 {
			target = resolved
		}
	}
	anchor := s.Now().UTC().Truncate(time.Microsecond)
	first := p.Intent
	first.Composition = &children[0].Composition
	wait := s.beginStorageWait(ctx, target, identity.Earlier(p.Deadline, identity.Earlier(i.ValidUntil, recovery.FreshUntil)), p.Storage)
	f, err := s.factsWithStorageWait(ctx, source, p.Actor, first, target, anchor, wait)
	wait.close()
	if err != nil {
		var changed contextStorageSelectionChange
		if errors.As(err, &changed) {
			return zero, s.requestChanged("storage")
		}
		return zero, err
	}
	if f.storage.Selection != p.Storage {
		return zero, s.requestChanged("storage")
	}
	if !slices.Equal(f.eligibility.DefaultAudience, p.Audience) {
		return zero, s.requestChanged("audience")
	}
	digest := ContextRequestDigest(p.ID)
	request := value.RecordingSaveGroupAdmission{Preview: p.Clone(), RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: digest, Recovery: recovery}
	coverageUntil := time.Time{}
	for n, c := range children {
		cp := compositionChild(p, n)
		fc, err := s.childRetention(ctx, f, c.Composition, p.Intent.RequestedSeconds, anchor)
		if err != nil {
			return zero, err
		}
		if !reflect.DeepEqual(retentionReview(fc.retention), c.Retention) {
			return zero, s.requestChanged("retention")
		}
		coverage, err := s.processingCoverage(ctx, cp, fc, recovery, i.ValidUntil)
		if err != nil {
			return zero, err
		}
		if coverageUntil.IsZero() || coverage.FreshUntil.Before(coverageUntil) {
			coverageUntil = coverage.FreshUntil
		}
		plan, err := s.recordingPlan(ctx, cp, fc)
		if err != nil {
			return zero, err
		}
		if plan.ScopeDigest != c.ScopeDigest || !bytes.Equal(plan.CanonicalScope, c.CanonicalScope) {
			return zero, s.requestChanged("scope")
		}
		if err = s.recordingAssessment(cp, plan); err != nil {
			return zero, s.requestChanged("assessment")
		}
		r := artifact.Registration{Location: artifact.Location{ClusterID: p.Target.ClusterID, ArtifactID: c.ArtifactID, AttemptID: c.AttemptID}, StoreID: p.Storage.StoreID, AllocationID: p.Storage.AllocationID, PoolRevision: p.Storage.PoolRevision, AllocationRevision: p.Storage.AllocationRevision, NativeLimit: nativeLimit(true), AnchorAt: fc.retention.AnchorAt, WriteUntil: identity.Earlier(p.Deadline, fc.retention.ExpiresAt), ExpiresAt: fc.retention.ExpiresAt, DeleteBy: fc.retention.DeleteBy}
		if r.Validate() != nil {
			return zero, value.ErrInvalid
		}
		rec, _, err := compiler.RecordingForContext(plan)
		if err != nil {
			return zero, s.requestChanged("recording")
		}
		if !s.Now().Add(time.Duration(rec.DurationMillis)*time.Millisecond + recordingCompletionMargin).Before(r.WriteUntil) {
			return zero, value.ErrAcquisitionClosed
		}
		request.Children = append(request.Children, value.Admission{Recovery: recovery, RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: digest, Plan: plan, Storage: f.storage.Binding, Registration: r, CaseID: p.CaseID, OccurrenceID: c.OccurrenceID})
	}
	final := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	final.ValidUntil = identity.Earlier(final.ValidUntil, f.eligibility.ValidUntil)
	final.VerifiedIdentity.ValidUntil = identity.Earlier(final.VerifiedIdentity.ValidUntil, i.ValidUntil)
	now := s.Now()
	if !final.Eligible || final.Target != target.Target() || final.Principal != p.Actor || final.VerifiedIdentity.Principal != p.Actor || !final.VerifiedIdentity.Valid(now) || !slices.Equal(final.DefaultAudience, p.Audience) || !now.Before(final.ValidUntil) || !s.factsCurrent(f, now) || !now.Before(coverageUntil) || !p.Current(now) || !recovery.Valid(now) || ctx.Err() != nil {
		return zero, s.requestChanged("eligibility")
	}
	for n := range request.Children {
		request.Children[n].Eligibility = final
		if !ReviewedCompositionGroupChild(p, n, request.Children[n]) {
			return zero, value.ErrChanged
		}
	}
	a, err := admit.AdmitRecordingCompositionGroup(ctx, request)
	if err != nil {
		return zero, previewFailure("request/admit-sql", err)
	}
	if !acceptedContext(a, digest) || a.CaptureID != p.CaptureID || a.ScopeDigest != p.ScopeDigest {
		return zero, value.ErrUnavailable
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !recovery.Valid(s.Now()) {
		return zero, previewFailure("request/identity-after", value.ErrDenied)
	}
	// ADR-276 v1: no parent history entry; repeating needs a new preview.
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, identity.Earlier(final.ValidUntil, final.VerifiedIdentity.ValidUntil))
	if !s.Now().Before(a.MetadataValidUntil) {
		return zero, previewFailure("request/metadata", value.ErrDenied)
	}
	return a, nil
}

// compositionGroupAccepted reports whether a is an accepted composition group.
func compositionGroupAccepted(a value.Accepted) bool {
	return a.Group != nil && len(a.Group.Children) > 0 && a.Group.Children[0].Expectation.CompositionGroup != nil
}

// dispatchCompositionGroup starts each accepted child serially under the
// requester's own identity, like a single manual recording. Sibling
// outcomes are separate; every child consumes its own acknowledged intent.
func (s ContextSubmission) dispatchCompositionGroup(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, a value.Accepted, check func() (context.Context, time.Time, error)) error {
	if !compositionGroupAccepted(a) || !acceptedContext(a, a.SubmissionDigest) {
		return value.ErrUnavailable
	}
	var failures []error
	// Every intent is acknowledged before any start: an intent's write window
	// is short from admission and must not wait for a sibling's start.
	ready := make([]bool, len(a.Group.Children))
	for n, child := range a.Group.Children {
		call, until, err := check()
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		end := identity.Earlier(until, identity.Earlier(child.Deadline, child.Expectation.Registration.WriteUntil))
		if !s.Now().Before(end) {
			failures = append(failures, value.ErrAcquisitionClosed)
			continue
		}
		childCall, cancel := context.WithDeadline(call, end)
		r, err := s.Intents.AcknowledgedCaptureIntent(childCall, child.CaptureID)
		cancel()
		if err != nil {
			s.reportGroupFailure("request/intent/" + auditapp.CaptureOperationFailureStage(err))
			failures = append(failures, value.ErrUnavailable)
			continue
		}
		raw, encodeErr := json.Marshal(child.Expectation)
		if encodeErr != nil || !r.Valid() || r.RootID != s.RootID || r.CaptureID != child.CaptureID || r.Requester() != i.Principal || r.Initiator != nil || r.ScopeDigest != child.ScopeDigest || r.SubmissionDigest != child.SubmissionDigest || r.ExpectationDigest != artifact.Digest(sha256.Sum256(raw)) || !r.Deadline.Equal(child.Deadline) || r.Group == nil || r.Group.ParentCaptureID != a.CaptureID || r.Group.ChildIndex != n || r.Group.ChildCount != len(a.Group.Children) {
			s.reportGroupFailure("request/intent/record")
			failures = append(failures, value.ErrUnavailable)
			continue
		}
		ready[n] = true
	}
	for n, child := range a.Group.Children {
		if !ready[n] {
			continue
		}
		call, until, err := check()
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		end := identity.Earlier(until, identity.Earlier(child.Deadline, child.Expectation.Registration.WriteUntil))
		if !s.Now().Before(end) {
			failures = append(failures, value.ErrAcquisitionClosed)
			continue
		}
		childCall, cancel := context.WithDeadline(call, end)
		err = s.Start.StartContext(childCall, current, child.CaptureID)
		cancel()
		if err != nil {
			s.reportGroupFailure("request/start/" + failureClass(err))
			failures = append(failures, err)
		}
	}
	if _, _, err := check(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (s ContextSubmission) reportGroupFailure(stage string) {
	if s.ReportPreviewFailure != nil {
		s.ReportPreviewFailure(stage)
	}
}
