package capture

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
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

type ContextTargets interface {
	ResolveWorkload(context.Context, targets.WorkloadRequest) (targets.PodResolution, error)
	ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
}

type ContextEligibilityReader interface {
	ContextEligibilityCurrent(context.Context, identities.CurrentIdentity, authorization.Target) authorization.CaptureEligibility
}

// ContextCapabilityReader returns protected, qualified configuration selected by
// installation composition. A diagnostic name or preview cannot enable a collector.
type ContextCapabilityReader interface {
	ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error)
}

type ContextRetentionResolver interface {
	Resolve(context.Context, privacy.Input) (privacy.Resolution, error)
}

type ContextStorageObservation struct {
	Selection value.ContextStorageSelection
	Binding   value.StorageBinding
}

type ContextStorageReader interface {
	ContextStorage(context.Context, authorization.Target) (ContextStorageObservation, error)
}

// ContextReasonObservation belongs to a separate current protected control-data
// reader. It checks exact ciphertext identity, actor/client, target and expiry;
// a caller-supplied reference alone cannot establish those facts.
type ContextReasonObservation struct {
	Reference              value.ProtectedReasonRef
	Actor                  identity.Principal
	Target                 authorization.Target
	ObservedAt, ValidUntil time.Time
}

type ContextReasonReader interface {
	ContextReason(context.Context, identities.CurrentIdentity, authorization.Target, value.ProtectedReasonRef) (ContextReasonObservation, error)
}

// ContextInvestigation is the shared browser/MCP use case for the exact bounded
// pod-status diagnostic. It does not dispatch work or publish/read evidence.
type ContextInvestigation struct {
	RootID, InstallationID string
	Previews               ContextPreviewStore
	Replay                 ContextAdmissionReplay
	Admission              ReviewedAdmissionTransaction
	Resolution             ContextRequestResolution
	Targets                ContextTargets
	Eligibility            ContextEligibilityReader
	Capabilities           ContextCapabilityReader
	Retention              ContextRetentionResolver
	Storage                ContextStorageReader
	Processing             ContextProcessingCoverageReader
	Recovery               fleetapp.RecoveryReader
	Reasons                ContextReasonReader
	Lifetime               time.Duration
	Now                    func() time.Time
	NewID                  func() string
}

// ContextPreviewResult includes a transient assessment of the same reviewed
// plan. Only Preview is persisted; assessment freshness never becomes authority.
type ContextPreviewResult struct {
	Preview    value.ContextPreview
	Assessment planning.ContextAssessment
	ValidUntil time.Time // Original metadata-delivery authority; never persisted.
}

type contextFacts struct {
	target      targets.PodResolution
	eligibility authorization.CaptureEligibility
	capability  planning.ContextCapability
	retention   privacy.Resolution
	storage     ContextStorageObservation
	reasonUntil time.Time
}

func (s ContextInvestigation) configured() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.Previews != nil && s.Replay != nil && s.Admission != nil && s.Targets != nil && s.Eligibility != nil && s.Capabilities != nil && s.Retention != nil && s.Storage != nil && s.Processing != nil && s.Recovery != nil && s.Lifetime >= time.Second && s.Lifetime <= 5*time.Minute && s.Lifetime%time.Microsecond == 0 && s.Now != nil && s.NewID != nil && compiler.ContextRecipeName == value.ContextDiagnosticName
}

func (s ContextInvestigation) currentRecovery(ctx context.Context) (artifact.RecoveryProof, error) {
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil {
		return artifact.RecoveryProof{}, err
	}
	if ctx.Err() != nil || !r.Valid(s.Now()) || r.InstallationID != s.InstallationID {
		return artifact.RecoveryProof{}, value.ErrUnavailable
	}
	return r, nil
}

func (s ContextInvestigation) currentIdentity(ctx context.Context, source identities.CurrentIdentity, actor identity.Principal, until time.Time) (identity.Identity, error) {
	i, err := source.ResolveIdentity(ctx)
	if err != nil {
		return identity.Identity{}, err
	}
	i.ValidUntil = identity.Earlier(i.ValidUntil, until)
	if ctx.Err() != nil || !i.Valid(s.Now()) || i.Principal != actor {
		return identity.Identity{}, value.ErrDenied
	}
	return i, nil
}

func (s ContextInvestigation) facts(ctx context.Context, source identities.CurrentIdentity, actor identity.Principal, intent value.ContextIntent, target targets.PodResolution, anchor time.Time) (contextFacts, error) {
	f := contextFacts{target: target}
	if !target.Valid(s.Now()) {
		return f, value.ErrChanged
	}
	t := target.Target()
	f.eligibility = s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	if !f.eligibility.Eligible || f.eligibility.Target != t || f.eligibility.Principal != actor || f.eligibility.VerifiedIdentity.Principal != actor || !f.eligibility.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(f.eligibility.ValidUntil) {
		return f, value.ErrDenied
	}
	var err error
	f.capability, err = s.Capabilities.ContextCapability(ctx, t)
	if err != nil {
		return f, err
	}
	f.retention, err = s.Retention.Resolve(ctx, privacy.Input{Target: t, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: intent.RequestedSeconds, AnchorAt: anchor})
	if err != nil {
		return f, err
	}
	f.storage, err = s.Storage.ContextStorage(ctx, t)
	if err != nil {
		return f, err
	}
	if intent.Reason != nil {
		if s.Reasons == nil {
			return f, value.ErrUnavailable
		}
		r, err := s.Reasons.ContextReason(ctx, source, t, *intent.Reason)
		if err != nil {
			return f, err
		}
		if r.Reference != *intent.Reason || r.Actor != actor || r.Target != t || !identity.Fresh(r.ObservedAt, r.ValidUntil, s.Now(), 5*time.Second) || r.ValidUntil.After(r.Reference.ExpiresAt) {
			return f, value.ErrDenied
		}
		f.reasonUntil = r.ValidUntil
	}
	if !s.factsCurrent(f, s.Now()) || ctx.Err() != nil {
		return f, value.ErrChanged
	}
	return f, nil
}

func (s ContextInvestigation) factsCurrent(f contextFacts, now time.Time) bool {
	t, b, p := f.target.Target(), f.storage.Binding, f.retention.Proof
	return f.target.Valid(now) && f.capability.Valid(now) && f.target.ExecutionClass == f.capability.ExecutionClass && f.capability.ProjectionDigest == compiler.ProjectionDigest() && b.Valid(now) && b.RootID == s.RootID && b.Matches(t) && f.storage.Selection.Valid() && b.AllocationID == f.storage.Selection.AllocationID && b.Revision == f.storage.Selection.BindingRevision && p.Valid(now) && p.Matches(s.RootID, t.ClusterID, t.NamespaceUID, t.WorkloadUID, t.PodUID) && p.Policy == f.retention.PolicyRevision && !f.retention.ValidUntil.After(p.ValidUntil) && now.Before(f.retention.ValidUntil) && now.Before(f.eligibility.ValidUntil) && f.eligibility.VerifiedIdentity.Valid(now) && (f.reasonUntil.IsZero() || now.Before(f.reasonUntil))
}

func retentionReview(r privacy.Resolution) value.ContextRetentionReview {
	policies := slices.Clone(r.Policies)
	slices.SortFunc(policies, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	return value.ContextRetentionReview{PurposeRef: r.PurposeRef, RequestedSeconds: r.RequestedSeconds, MaximumSeconds: r.MaximumSeconds, DeletionBudgetSeconds: r.DeletionBudgetSeconds, Policies: policies}
}

func (s ContextInvestigation) plan(p value.ContextPreview, f contextFacts) (planning.ContextPlan, error) {
	return compiler.CompileContext(planning.ContextInput{CaptureID: p.CaptureID, CaseID: p.CaseID, Executor: p.Actor, Deadline: p.Deadline, Target: f.target, Retention: f.retention, Capability: f.capability}, s.Now())
}

// Preview observes authorized metadata and writes only a bounded draft. It does
// not reserve custody/storage, write acquisition intent or start a collector.
func (s ContextInvestigation) Preview(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent) (ContextPreviewResult, error) {
	var zero ContextPreviewResult
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if intent.Diagnostic != value.ContextDiagnosticName {
		return zero, value.ErrDiagnosticUnavailable
	}
	if !intent.Valid() {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	created := s.Now().UTC().Truncate(time.Microsecond)
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return zero, err
	}
	target, err := s.Targets.ResolveWorkload(ctx, intent.Target)
	if err != nil {
		return zero, err
	}
	f, err := s.facts(ctx, source, i.Principal, intent, target, created)
	if err != nil {
		return zero, err
	}
	p := value.ContextPreview{ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Storage: f.storage.Selection, Retention: retentionReview(f.retention), Audience: slices.Clone(f.eligibility.DefaultAudience), CreatedAt: created, Deadline: created.Add(s.Lifetime)}
	p.ExecutionClass = target.ExecutionClass
	p.AssessmentID, p.AssessmentRulesDigest = s.NewID(), compiler.ContextAssessmentRulesDigestForClass(target.ExecutionClass)
	if intent.Reason != nil {
		p.Deadline = identity.Earlier(p.Deadline, intent.Reason.ExpiresAt)
	}
	coverage, err := s.processingCoverage(ctx, p, f, recovery, i.ValidUntil)
	if err != nil {
		return zero, err
	}
	ctx, coverageEnd := context.WithDeadline(ctx, coverage.FreshUntil)
	defer coverageEnd()
	plan, err := s.plan(p, f)
	if err != nil {
		return zero, err
	}
	p.CanonicalScope, p.ScopeDigest = slices.Clone(plan.CanonicalScope), plan.ScopeDigest
	assessment, err := compiler.AssessContext(plan, p.AssessmentID, s.Now())
	if err != nil {
		return zero, err
	}
	if !ValidContextPreview(p) || !p.Current(s.Now()) {
		return zero, value.ErrInvalid
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) {
		return zero, value.ErrChanged
	}
	if err = s.Previews.CreateContextPreview(ctx, p.Clone()); err != nil {
		return zero, err
	}
	// An uncertain draft write may consume one passive slot, never execution.
	// Current rights and every original observation also bound the response.
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	if !current.Eligible || current.Target != target.Target() || current.Principal != i.Principal || !current.VerifiedIdentity.Valid(s.Now()) || !i.Valid(s.Now()) || !slices.Equal(current.DefaultAudience, p.Audience) || !s.Now().Before(current.ValidUntil) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil || s.Now().Before(created) {
		return zero, value.ErrChanged
	}
	until := identity.Earlier(i.ValidUntil, recovery.FreshUntil)
	until = identity.Earlier(until, current.ValidUntil)
	until = identity.Earlier(until, current.VerifiedIdentity.ValidUntil)
	until = identity.Earlier(until, f.eligibility.ValidUntil)
	until = identity.Earlier(until, f.eligibility.VerifiedIdentity.ValidUntil)
	until = identity.Earlier(until, assessment.ValidUntil)
	until = identity.Earlier(until, f.storage.Binding.FreshUntil)
	until = identity.Earlier(until, coverage.FreshUntil)
	if !f.reasonUntil.IsZero() {
		until = identity.Earlier(until, f.reasonUntil)
	}
	if !s.Now().Before(until) || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	return ContextPreviewResult{Preview: p.Clone(), Assessment: assessment, ValidUntil: until}, nil
}

func acceptedContext(a value.Accepted, digest artifact.Digest) bool {
	e := a.Expectation
	return authorization.UUID(a.CaptureID) && a.CaptureID == e.CaptureUID && a.SubmissionDigest == digest && a.ScopeDigest == e.PlanDigest && e.Validate() == nil && !a.CreatedAt.IsZero() && a.Deadline.After(a.CreatedAt) && (a.State == value.PendingAudit || a.State == value.IntentAudited) && a.Pin.Namespace == e.Namespace && a.Pin.NamespaceUID == e.NamespaceUID && a.Pin.UID == e.PodUID
}

// Request resolves accepted idempotency before touching a preview. Existing
// operation lookup never needs a live pod or fresh acquisition facts. Only a
// missing original key may refresh the reviewed blueprint and enter admission.
func (s ContextInvestigation) Request(ctx context.Context, source identities.CurrentIdentity, previewID, key string) (value.Accepted, error) {
	var zero value.Accepted
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(previewID) || !identity.Text(key, 128) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.Now()
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return zero, err
	}
	digest := ContextRequestDigest(previewID)
	q := value.ReplayQuery{RootID: s.RootID, PreviewID: previewID, IdempotencyKey: key, SubmissionDigest: digest, Identity: i, Recovery: recovery}
	previous, found, err := s.Replay.LookupContextAdmission(ctx, q)
	if err != nil {
		return zero, err
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !recovery.Valid(s.Now()) || s.Now().Before(started) {
		return zero, value.ErrDenied
	}
	if found {
		previous.MetadataValidUntil = identity.Earlier(previous.MetadataValidUntil, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
		if !acceptedContext(previous, digest) || !s.Now().Before(previous.MetadataValidUntil) {
			return zero, value.ErrUnavailable
		}
		previous.Replay = true
		return previous, nil
	}
	p, err := s.Previews.ReadContextPreview(ctx, s.RootID, previewID, i.Principal)
	if err != nil {
		return zero, err
	}
	p = p.Clone()
	if !ValidContextPreview(p) || p.ID != previewID || p.RootID != s.RootID || p.InstallationID != s.InstallationID || p.Actor != i.Principal {
		return zero, value.ErrDenied
	}
	if !p.Current(s.Now()) {
		return zero, value.ErrPreviewExpired
	}
	if p.IssuerEpoch != recovery.IssuerEpoch || p.AssessmentRulesDigest != compiler.ContextAssessmentRulesDigestForClass(p.ExecutionClass) {
		return zero, value.ErrChanged
	}
	target, err := s.Targets.ResolvePod(ctx, p.Target)
	if err != nil {
		return zero, err
	}
	if target.Request != p.Target || target.Pin != p.Pin || target.ExecutionClass != p.ExecutionClass {
		return zero, value.ErrChanged
	}
	anchor := s.Now().UTC().Truncate(time.Microsecond)
	f, err := s.facts(ctx, source, i.Principal, p.Intent, target, anchor)
	if err != nil {
		return zero, err
	}
	coverage, err := s.processingCoverage(ctx, p, f, recovery, i.ValidUntil)
	if err != nil {
		return zero, err
	}
	ctx, coverageEnd := context.WithDeadline(ctx, coverage.FreshUntil)
	defer coverageEnd()
	plan, err := s.plan(p, f)
	if err != nil {
		return zero, err
	}
	if plan.ScopeDigest != p.ScopeDigest || !bytes.Equal(plan.CanonicalScope, p.CanonicalScope) || f.storage.Selection != p.Storage || !reflect.DeepEqual(retentionReview(f.retention), p.Retention) || !slices.Equal(f.eligibility.DefaultAudience, p.Audience) {
		return zero, value.ErrChanged
	}
	assessment, err := compiler.AssessContext(plan, p.AssessmentID, s.Now())
	if err != nil || assessment.RulesDigest != p.AssessmentRulesDigest {
		return zero, value.ErrChanged
	}
	// The evidence interval starts at actual request preparation, not preview.
	// A concurrent request can win with another anchor; SQL replay returns its
	// original immutable registration and never creates a second reservation.
	r := artifact.Registration{Location: artifact.Location{ClusterID: p.Target.ClusterID, ArtifactID: p.ArtifactID, AttemptID: p.AttemptID}, StoreID: p.Storage.StoreID, AllocationID: p.Storage.AllocationID, PoolRevision: p.Storage.PoolRevision, AllocationRevision: p.Storage.AllocationRevision, NativeLimit: artifact.MaxContextBytes, AnchorAt: f.retention.AnchorAt, WriteUntil: identity.Earlier(p.Deadline, f.retention.ExpiresAt), ExpiresAt: f.retention.ExpiresAt, DeleteBy: f.retention.DeleteBy}
	if r.Validate() != nil {
		return zero, value.ErrInvalid
	}
	final := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	final.ValidUntil = identity.Earlier(final.ValidUntil, f.eligibility.ValidUntil)
	final.VerifiedIdentity.ValidUntil = identity.Earlier(final.VerifiedIdentity.ValidUntil, i.ValidUntil)
	if !final.Eligible || final.Target != target.Target() || final.Principal != p.Actor || final.VerifiedIdentity.Principal != p.Actor || !final.VerifiedIdentity.Valid(s.Now()) || !slices.Equal(final.DefaultAudience, p.Audience) || !s.Now().Before(final.ValidUntil) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !p.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrChanged
	}
	a, err := s.Admission.AdmitReviewedContext(ctx, p.ID, value.Admission{Recovery: recovery, RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: digest, Plan: plan, Eligibility: final, Storage: f.storage.Binding, Registration: r, CaseID: p.CaseID, OccurrenceID: p.OccurrenceID})
	if err != nil {
		return zero, err
	}
	if !acceptedContext(a, digest) || a.CaptureID != p.CaptureID || a.ScopeDigest != p.ScopeDigest || a.Pin != p.Pin || a.Expectation.ExecutionClass != p.ExecutionClass || a.Expectation.CaseID != p.CaseID || a.Expectation.OccurrenceID != p.OccurrenceID || a.Expectation.Registration.Location != r.Location || a.Expectation.Registration.StoreID != r.StoreID || a.Expectation.Registration.AllocationID != r.AllocationID || a.Expectation.Registration.PoolRevision != r.PoolRevision || a.Expectation.Registration.AllocationRevision != r.AllocationRevision || a.Expectation.Registration.NativeLimit != r.NativeLimit || !a.Deadline.Equal(p.Deadline) {
		return zero, value.ErrUnavailable
	}
	if !a.Replay && a.Expectation.Registration != r {
		return zero, value.ErrUnavailable
	}
	// Effects may already be committed when a response becomes unavailable. The
	// next call recovers the original operation through the read-only lookup.
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !recovery.Valid(s.Now()) || s.Now().Before(started) {
		return zero, value.ErrDenied
	}
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, identity.Earlier(final.ValidUntil, final.VerifiedIdentity.ValidUntil))
	if !s.Now().Before(a.MetadataValidUntil) {
		return zero, value.ErrDenied
	}
	return a, nil
}
