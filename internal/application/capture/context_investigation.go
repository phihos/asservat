package capture

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
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

// ContextCapacityRefresh records a short-lived demand that the hub-worker
// refresh one enrolled workload's binding (ADR-200). It names a workload and
// confers no authority; the worker still performs every check.
type ContextCapacityRefresh interface {
	DemandCapacityRefresh(context.Context, targets.Request) error
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
	Refresh                ContextCapacityRefresh // optional (ADR-200)
	Processing             ContextProcessingCoverageReader
	Recovery               fleetapp.RecoveryReader
	Reasons                ContextReasonReader
	Lifetime               time.Duration
	Now                    func() time.Time
	NewID                  func() string
	// ReportPreviewFailure receives only fixed private stage labels. It is
	// diagnostic, synchronous and must not perform blocking work or grant authority.
	ReportPreviewFailure func(string)
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

func (s ContextInvestigation) facts(ctx context.Context, source identities.CurrentIdentity, actor identity.Principal, intent value.ContextIntent, target targets.PodResolution, anchor, originalUntil time.Time) (contextFacts, error) {
	if !target.Valid(s.Now()) {
		return contextFacts{target: target}, previewFailure("facts/target", value.ErrChanged)
	}
	wait := s.beginStorageWait(ctx, target, originalUntil, value.ContextStorageSelection{})
	defer wait.close()
	return s.factsWithStorageWait(ctx, source, actor, intent, target, anchor, wait)
}

func (s ContextInvestigation) factsWithStorageWait(ctx context.Context, source identities.CurrentIdentity, actor identity.Principal, intent value.ContextIntent, target targets.PodResolution, anchor time.Time, storageWait *contextStorageWait) (contextFacts, error) {
	f := contextFacts{target: target}
	if !target.Valid(s.Now()) {
		return f, previewFailure("facts/target", value.ErrChanged)
	}
	t := target.Target()
	mark := time.Now()
	f.eligibility = s.Eligibility.ContextEligibilityCurrent(ctx, source, t)
	auditapp.MarkStep(ctx, "p-eligibility", mark)
	if !f.eligibility.Eligible || f.eligibility.Target != t || f.eligibility.Principal != actor || f.eligibility.VerifiedIdentity.Principal != actor || !f.eligibility.VerifiedIdentity.Valid(s.Now()) || !s.Now().Before(f.eligibility.ValidUntil) {
		return f, previewFailure(previewEligibilityFailure(f.eligibility.Reason), value.ErrDenied)
	}
	var err error
	mark = time.Now()
	f.capability, err = s.Capabilities.ContextCapability(ctx, t)
	auditapp.MarkStep(ctx, "p-capability", mark)
	if err != nil {
		return f, previewFailure("facts/capability", err)
	}
	mark = time.Now()
	f.retention, err = s.Retention.Resolve(ctx, privacy.Input{Target: t, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: intent.RequestedSeconds, AnchorAt: anchor})
	auditapp.MarkStep(ctx, "p-retention", mark)
	if err != nil {
		return f, previewFailure("facts/retention/"+retentionFailure(err), err)
	}
	// The one readiness owner joins its early hint and consumes a fresh,
	// independently read binding within every retained non-storage bound.
	mark = time.Now()
	f.storage, err = s.consumeStorage(ctx, f, intent, storageWait)
	auditapp.MarkStep(ctx, "p-storage", mark)
	if err != nil {
		return f, err
	}
	if intent.Reason != nil {
		if s.Reasons == nil {
			return f, previewFailure("facts/reason", value.ErrUnavailable)
		}
		r, err := s.Reasons.ContextReason(ctx, source, t, *intent.Reason)
		if err != nil {
			return f, previewFailure("facts/reason", err)
		}
		if r.Reference != *intent.Reason || r.Actor != actor || r.Target != t || !identity.Fresh(r.ObservedAt, r.ValidUntil, s.Now(), 5*time.Second) || r.ValidUntil.After(r.Reference.ExpiresAt) {
			return f, previewFailure("facts/reason", value.ErrDenied)
		}
		f.reasonUntil = r.ValidUntil
	}
	if !s.factsCurrent(f, s.Now()) || ctx.Err() != nil {
		return f, previewFailure("facts/current", value.ErrChanged)
	}
	return f, nil
}

func (s ContextInvestigation) factsCurrent(f contextFacts, now time.Time) bool {
	return s.nonStorageFactsCurrent(f, now) && s.storageCurrent(f.storage, f.target.Target(), now)
}

func (s ContextInvestigation) nonStorageFactsCurrent(f contextFacts, now time.Time) bool {
	t, p := f.target.Target(), f.retention.Proof
	return f.target.Valid(now) && f.capability.Valid(now) && f.target.ExecutionClass == f.capability.ExecutionClass && f.capability.ProjectionDigest == compiler.ProjectionDigest() && p.Valid(now) && p.Matches(s.RootID, t.ClusterID, t.NamespaceUID, t.WorkloadUID, t.PodUID) && p.Policy == f.retention.PolicyRevision && !f.retention.ValidUntil.After(p.ValidUntil) && now.Before(f.retention.ValidUntil) && now.Before(f.eligibility.ValidUntil) && f.eligibility.VerifiedIdentity.Valid(now) && (f.reasonUntil.IsZero() || now.Before(f.reasonUntil))
}

func (s ContextInvestigation) storageCurrent(v ContextStorageObservation, t authorization.Target, now time.Time) bool {
	b := v.Binding
	return b.Valid(now) && b.RootID == s.RootID && b.Matches(t) && v.Selection.Valid() && b.AllocationID == v.Selection.AllocationID && b.Revision == v.Selection.BindingRevision
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
func (s ContextInvestigation) Preview(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent) (result ContextPreviewResult, failure error) {
	return s.preview(ctx, source, intent, nil)
}

// PreviewRepeat is Preview for "Collect again" (ADR-236): every current check
// runs exactly as for a new preview, and the named workload must still
// resolve to the original namespace and workload identity. A recreated
// workload is reported only after current collection eligibility on it.
func (s ContextInvestigation) PreviewRepeat(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent, original authorization.Target) (result ContextPreviewResult, failure error) {
	if !authorization.UUID(original.ClusterID) || !identity.Text(original.NamespaceUID, 64) || !identity.Text(original.WorkloadUID, 64) {
		return ContextPreviewResult{}, previewFailure("repeat/original", value.ErrInvalid)
	}
	return s.preview(ctx, source, intent, &original)
}

func (s ContextInvestigation) preview(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent, original *authorization.Target) (result ContextPreviewResult, failure error) {
	defer func() { s.reportPreviewFailure(failure) }()
	var zero ContextPreviewResult
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return zero, previewFailure("configuration", value.ErrUnavailable)
	}
	if intent.Diagnostic != value.ContextDiagnosticName {
		return zero, previewFailure("diagnostic", value.ErrDiagnosticUnavailable)
	}
	if !intent.Valid() {
		return zero, previewFailure("intent", value.ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	created := s.Now().UTC().Truncate(time.Microsecond)
	mark := time.Now()
	i, err := source.ResolveIdentity(ctx)
	auditapp.MarkStep(ctx, "p-identity", mark)
	if err != nil || !i.Valid(s.Now()) {
		return zero, previewFailure("identity", value.ErrDenied)
	}
	if err = previewSharing(intent.Sharing, i, created); err != nil {
		return zero, previewFailure("sharing", err)
	}
	mark = time.Now()
	recovery, err := s.currentRecovery(ctx)
	auditapp.MarkStep(ctx, "p-recovery", mark)
	if err != nil {
		return zero, previewFailure("recovery", err)
	}
	mark = time.Now()
	target, err := s.Targets.ResolveWorkload(ctx, intent.Target)
	auditapp.MarkStep(ctx, "p-target", mark)
	if err != nil {
		return zero, previewFailure("target", err)
	}
	f, err := s.facts(ctx, source, i.Principal, intent, target, created, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	if err != nil {
		return zero, previewFailure("facts", err)
	}
	if original != nil && (target.Request.ClusterID != original.ClusterID || target.Request.Namespace.UID != original.NamespaceUID || target.Request.Workload.UID != original.WorkloadUID) {
		return zero, previewFailure("repeat/target", value.ErrTargetReplaced)
	}
	p := value.ContextPreview{ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Storage: f.storage.Selection, Retention: retentionReview(f.retention), Audience: slices.Clone(f.eligibility.DefaultAudience), CreatedAt: created, Deadline: created.Add(s.Lifetime)}
	p.ExecutionClass = target.ExecutionClass
	p.AssessmentID, p.AssessmentRulesDigest = s.NewID(), compiler.ContextAssessmentRulesDigestForClass(target.ExecutionClass)
	if intent.Reason != nil {
		p.Deadline = identity.Earlier(p.Deadline, intent.Reason.ExpiresAt)
	}
	processingStarted := time.Now()
	coverage, err := s.processingCoverage(ctx, p, f, recovery, i.ValidUntil)
	auditapp.MarkStep(ctx, "p-processing", processingStarted)
	if err != nil {
		return zero, previewFailure("processing", err)
	}
	ctx, coverageEnd := context.WithDeadline(ctx, coverage.FreshUntil)
	defer coverageEnd()
	plan, err := s.plan(p, f)
	if err != nil {
		return zero, previewFailure("compile", err)
	}
	p.CanonicalScope, p.ScopeDigest = slices.Clone(plan.CanonicalScope), plan.ScopeDigest
	assessment, err := compiler.AssessContext(plan, p.AssessmentID, s.Now())
	if err != nil {
		return zero, previewFailure("assessment", err)
	}
	if !ValidContextPreview(p) || !p.Current(s.Now()) {
		return zero, previewFailure("blueprint", value.ErrInvalid)
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) {
		return zero, previewFailure("before-store/current", value.ErrChanged)
	}
	mark = time.Now()
	err = s.Previews.CreateContextPreview(ctx, p.Clone())
	auditapp.MarkStep(ctx, "p-store", mark)
	if err != nil {
		return zero, previewFailure("store", err)
	}
	// An uncertain draft write may consume one passive slot, never execution.
	// Current rights and every original observation also bound the response.
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	if !current.Eligible || current.Target != target.Target() || current.Principal != i.Principal || !current.VerifiedIdentity.Valid(s.Now()) || !i.Valid(s.Now()) || !slices.Equal(current.DefaultAudience, p.Audience) || !s.Now().Before(current.ValidUntil) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil || s.Now().Before(created) {
		return zero, previewFailure("after-store/current", value.ErrChanged)
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
		return zero, previewFailure("response/current", value.ErrUnavailable)
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
func (s ContextInvestigation) Request(ctx context.Context, source identities.CurrentIdentity, previewID, key string) (result value.Accepted, failure error) {
	defer func() { s.reportRequestFailure(failure) }()
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
		return zero, s.requestChanged("epoch")
	}
	// The storage wait needs only the preview's pinned target, so it runs
	// beside the target re-resolution instead of after it. It confers nothing:
	// facts still read and check storage after both, and the wait is joined
	// before the request returns.
	storageWait := s.beginStorageWait(ctx, targets.PodResolution{Request: p.Target}, identity.Earlier(p.Deadline, identity.Earlier(i.ValidUntil, recovery.FreshUntil)), p.Storage)
	defer storageWait.close()
	resolveStarted := time.Now()
	target, err := s.Targets.ResolvePod(ctx, p.Target)
	auditapp.MarkStep(ctx, "q-resolve", resolveStarted)
	if err != nil {
		// Reported with its closed class; the error still unwraps unchanged.
		return zero, previewFailure("target/"+targetFailureClass(err), err)
	}
	if target.Request != p.Target || target.Pin != p.Pin || target.ExecutionClass != p.ExecutionClass {
		return zero, s.requestChanged("target")
	}
	anchor := s.Now().UTC().Truncate(time.Microsecond)
	f, err := s.factsWithStorageWait(ctx, source, i.Principal, p.Intent, target, anchor, storageWait)
	if err != nil {
		var changed contextStorageSelectionChange
		if errors.As(err, &changed) {
			return zero, s.requestChanged("storage")
		}
		return zero, err
	}
	processingStarted := time.Now()
	coverage, err := s.processingCoverage(ctx, p, f, recovery, i.ValidUntil)
	auditapp.MarkStep(ctx, "p-processing", processingStarted)
	if err != nil {
		return zero, err
	}
	ctx, coverageEnd := context.WithDeadline(ctx, coverage.FreshUntil)
	defer coverageEnd()
	plan, err := s.plan(p, f)
	if err != nil {
		return zero, err
	}
	if plan.ScopeDigest != p.ScopeDigest || !bytes.Equal(plan.CanonicalScope, p.CanonicalScope) {
		return zero, s.requestChanged("scope")
	}
	if f.storage.Selection != p.Storage {
		return zero, s.requestChanged("storage")
	}
	if !reflect.DeepEqual(retentionReview(f.retention), p.Retention) {
		return zero, s.requestChanged("retention")
	}
	if !slices.Equal(f.eligibility.DefaultAudience, p.Audience) {
		return zero, s.requestChanged("audience")
	}
	assessment, err := compiler.AssessContext(plan, p.AssessmentID, s.Now())
	if err != nil || assessment.RulesDigest != p.AssessmentRulesDigest {
		return zero, s.requestChanged("assessment")
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
	// One label per failed condition; the outcome is the same ReviewChanged.
	now := s.Now()
	for _, c := range []struct {
		failed bool
		stage  string
	}{
		{!final.Eligible, "eligibility/denied"},
		{final.Target != target.Target() || final.Principal != p.Actor || final.VerifiedIdentity.Principal != p.Actor, "eligibility/subject"},
		{!final.VerifiedIdentity.Valid(now), "eligibility/identity"},
		{!slices.Equal(final.DefaultAudience, p.Audience), "eligibility/audience"},
		{!now.Before(final.ValidUntil), "eligibility/expired"},
		{!s.factsCurrent(f, now), "eligibility/facts"},
		{!coverage.Current(now), "eligibility/coverage"},
		{!p.Current(now), "eligibility/preview"},
		{!recovery.Valid(now), "eligibility/recovery"},
		{ctx.Err() != nil, "eligibility/deadline"},
	} {
		if c.failed {
			return zero, s.requestChanged(c.stage)
		}
	}
	admitStarted := time.Now()
	a, err := s.Admission.AdmitReviewedContext(ctx, p.ID, value.Admission{Recovery: recovery, RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: digest, Plan: plan, Eligibility: final, Storage: f.storage.Binding, Registration: r, CaseID: p.CaseID, OccurrenceID: p.OccurrenceID})
	auditapp.MarkStep(ctx, "q-admit", admitStarted)
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

// This private marker distinguishes the final margin refusal without changing
// the existing preview stage or public error classification.
type contextStorageMarginRefusal struct{}

func (contextStorageMarginRefusal) Error() string { return "context storage margin unavailable" }
func (contextStorageMarginRefusal) Unwrap() error { return value.ErrUnavailable }

func (s ContextInvestigation) reportRequestFailure(err error) {
	var failure *contextPreviewFailure
	if s.ReportPreviewFailure == nil || !errors.As(err, &failure) {
		return
	}
	stage := failure.stage
	if stage == "facts/storage" {
		if _, margin := failure.cause.(contextStorageMarginRefusal); margin {
			stage += "/margin"
		} else {
			stage += "/read"
			var read interface{ ContextStorageRead() string }
			if errors.As(failure.cause, &read) {
				switch detail := read.ContextStorageRead(); detail {
				case "transaction", "observation",
					"query/no-row", "query/deadline", "query/canceled", "query/unavailable",
					"clock/no-row", "clock/deadline", "clock/canceled", "clock/unavailable":
					stage += "/" + detail
				}
			}
		}
	}
	s.ReportPreviewFailure("request/" + stage)
}

// storageMargin is the binding freshness required by both the readiness hint
// and the authoritative read before subsequent processing/admission checks.
const storageMargin = time.Second

// retentionFailure names a closed retention failure class for diagnostics.
func retentionFailure(err error) string {
	var read interface{ RetentionRead() string }
	switch {
	case errors.As(err, &read):
		switch step := read.RetentionRead(); step {
		case "topology", "source-hub", "source-region", "selector-limit", "selectors-absent", "selectors", "final-topology", "final-sources", "final-source", "fresh":
			return "read/" + step
		}
		return "read"
	case errors.Is(err, privacy.ErrInvalid):
		return "invalid"
	case errors.Is(err, privacy.ErrConflict):
		return "conflict"
	case errors.Is(err, privacy.ErrExpired):
		return "expired"
	case errors.Is(err, privacy.ErrUnavailable):
		return "unavailable"
	default:
		return "other"
	}
}

// requestChanged reports a request's changed-review stage, a fixed label.
func (s ContextInvestigation) requestChanged(stage string) error {
	if s.ReportPreviewFailure != nil {
		s.ReportPreviewFailure("request/changed/" + stage)
	}
	return value.ErrChanged
}

// targetFailureClass names a target resolution failure for the operator
// report only.
func targetFailureClass(err error) string {
	for _, c := range []struct {
		name string
		err  error
	}{{"changed", targets.ErrChanged}, {"denied", targets.ErrDenied}, {"unscheduled", targets.ErrUnscheduled}, {"unavailable", targets.ErrUnavailable}} {
		if errors.Is(err, c.err) {
			return c.name
		}
	}
	return "other"
}
