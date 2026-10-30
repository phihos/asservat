package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// SnapshotAudience intersects the complete original source audience with the
// complete current audience. New assignments cannot grant access to old bytes.
// Legacy sources lacking their original audience cannot be saved.
func SnapshotAudience(selected *planning.SourceSnapshotContext, current []artifact.AudienceAssignment) ([]artifact.AudienceAssignment, error) {
	if selected == nil {
		return slices.Clone(current), nil
	}
	digest, err := compiler.SourceAudienceDigest(selected.SourceAudience)
	if err != nil || digest != selected.SourceAudienceDigest {
		return nil, value.ErrChanged
	}
	var out []artifact.AudienceAssignment
	for _, a := range current {
		if slices.Contains(selected.SourceAudience, a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, value.ErrDenied
	}
	return out, nil
}

// PolicySnapshotSelection comes only from the current accepted policy and its
// retained exact source row. It is not a public source handle or an arm permit.
type PolicySnapshotSelection struct {
	Policy      value.RestartPolicy
	Authority   authorization.AcceptedPolicyAuthority
	Source      PolicySourceState
	Target      targets.Request
	TriggeredAt time.Time
}

// PreviewPolicySnapshot prepares only the requested existing-source window.
// It uses the shared preview/admission path and cannot invoke another action.
func (s ContextInvestigation) PreviewPolicySnapshot(ctx context.Context, current identities.CurrentIdentity, selection PolicySnapshotSelection) (ContextPreviewResult, error) {
	var zero ContextPreviewResult
	if !s.configured() || ctx == nil || current == nil {
		return zero, value.ErrUnavailable
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	now := s.Now().UTC().Truncate(time.Microsecond)
	p, a, source := selection.Policy, selection.Authority, selection.Source
	if !p.Valid() || p.Recorder == nil || p.Recorder.Action.ExecutionMode != "ongoing" || !a.Valid(now) || selection.TriggeredAt.IsZero() || selection.TriggeredAt.After(now) || source.Binding.Scope != [32]byte(a.ScopeDigest) || source.Binding.PodUID != selection.Target.PodUID || source.Binding.PolicyUID != a.PolicyUID || source.ClusterID != a.ClusterID || source.NamespaceUID != a.NamespaceUID || source.WorkloadUID != a.WorkloadUID {
		return zero, previewFailure("snapshot/selection", value.ErrChanged)
	}
	before, e1 := time.ParseDuration(p.Recorder.Action.Before)
	after, e2 := time.ParseDuration(p.Recorder.Action.After)
	actionTimeout, e3 := time.ParseDuration(p.Recorder.Action.Timeout)
	recipeTimeout, e4 := time.ParseDuration(p.Recorder.Composition.MaxDuration)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || actionTimeout <= 0 || recipeTimeout <= 0 {
		return zero, value.ErrInvalid
	}
	deadline := identity.Earlier(now.Add(min(actionTimeout, recipeTimeout)), a.NotAfter).UTC()
	audienceDigest, err := compiler.SourceAudienceDigest(source.Audience)
	if err != nil || audienceDigest != artifact.Digest(source.Binding.AudienceDigest) {
		return zero, previewFailure("snapshot/audience", value.ErrChanged)
	}
	raw, err := json.Marshal(source.Binding)
	if err != nil {
		return zero, err
	}
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(sha256.Sum256(raw)), SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, SnapshotID: s.NewID(), SourceStartedAt: source.StartedAt.UTC(), SourceHardUntil: source.HardUntil.UTC(), T0: selection.TriggeredAt.UTC(), IssuedAt: now, StartBy: identity.Earlier(now.Add(5*time.Second), identity.Earlier(source.HardUntil, deadline.Add(-time.Microsecond))), ProcessingUntil: deadline, Before: before, After: after, MaxBytes: min(p.Recorder.Action.MaxBytes, int64(artifact.RecordingNativeLimit))}
	if !request.Valid() {
		return zero, value.ErrAcquisitionClosed
	}
	selected := &planning.SourceSnapshotContext{Request: request, ActionID: source.Binding.ActionID, PolicyUID: a.PolicyUID, TriggerKind: "policy", ExecutionDigest: a.ScopeDigest, RecipeDigest: p.Recorder.RecipeDigest, SourceAudience: slices.Clone(source.Audience), SourceAudienceDigest: audienceDigest, SourceTarget: source.Target}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal != a.Executor {
		return zero, value.ErrDenied
	}
	required, err := s.requireRecordingApproval(ctx, current, i.Principal)
	if err != nil {
		return zero, err
	}
	selected.Request.RequireApproval = required
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return zero, err
	}
	target, observed, err := s.resolveSourceSnapshot(ctx, selected)
	if err != nil {
		return zero, err
	}
	if target.Request != selection.Target {
		return zero, targets.ErrChanged
	}
	intent := value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: selection.Target.ClusterID, Namespace: selection.Target.Namespace.Name, Kind: "Pod", Name: selection.Target.PodName}, RequestedSeconds: p.RetentionSeconds, Snapshot: selected, HistoryAuthored: p.HistoryAuthored.Clone()}
	wait := s.beginStorageWait(ctx, target, identity.Earlier(i.ValidUntil, recovery.FreshUntil), value.ContextStorageSelection{})
	defer wait.close()
	f, err := s.factsWithStorageWait(ctx, current, a.Executor, intent, target, artifact.SourceSnapshotAnchor(request), wait, *observed)
	if err != nil {
		return zero, err
	}
	selected.Request.ProcessingUntil = identity.Earlier(selected.Request.ProcessingUntil, f.retention.ExpiresAt).UTC()
	selected.Request.StartBy = identity.Earlier(selected.Request.StartBy, selected.Request.ProcessingUntil.Add(-time.Microsecond)).UTC()
	if !selected.Request.Valid() {
		return zero, value.ErrAcquisitionClosed
	}
	preview := value.ContextPreview{ExecutionClass: target.ExecutionClass, ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), AssessmentID: s.NewID(), AssessmentRulesDigest: compiler.SourceSnapshotAssessmentRulesDigest(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Storage: f.storage.Selection, Retention: retentionReview(f.retention), Audience: slices.Clone(f.eligibility.DefaultAudience), CreatedAt: now, Deadline: selected.Request.ProcessingUntil, SelectionUntil: now.Add(min(s.Lifetime, time.Minute))}
	plan, err := s.plan(preview, f)
	if err != nil {
		return zero, err
	}
	preview.CanonicalScope, preview.ScopeDigest = slices.Clone(plan.CanonicalScope), plan.ScopeDigest
	assessment, err := compiler.AssessContext(plan, preview.AssessmentID, s.Now())
	if err != nil {
		return zero, err
	}
	coverage, err := s.processingCoverage(ctx, preview, f, recovery, i.ValidUntil)
	if err != nil {
		return zero, err
	}
	if !ValidContextPreview(preview) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) {
		return zero, previewFailure("snapshot/before-store", value.ErrChanged)
	}
	if err = s.Previews.CreateContextPreview(ctx, preview.Clone()); err != nil {
		return zero, err
	}
	fresh := s.Eligibility.ContextEligibilityCurrent(ctx, current, target.Target())
	freshAudience, err := SnapshotAudience(selected, fresh.DefaultAudience)
	if err != nil || !fresh.Eligible || !fresh.VerifiedIdentity.Valid(s.Now()) || !fresh.VerifiedIdentity.ValidUntil.After(s.Now()) || !slices.Equal(freshAudience, preview.Audience) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil {
		return zero, previewFailure("snapshot/after-store", value.ErrChanged)
	}
	until := identity.Earlier(plan.ValidUntil, identity.Earlier(i.ValidUntil, identity.Earlier(fresh.ValidUntil, coverage.FreshUntil)))
	return ContextPreviewResult{CollectorImageDigest: f.capability.CollectorImageDigest, ProjectionDigest: f.capability.ProjectionDigest, Preview: preview.Clone(), Assessment: assessment, ValidUntil: until}, nil
}

// Existing-source resolution intentionally supplies no fresh Pod RV or Pod
// observation time. The typed source report supplies its own current proof.
type SourceSnapshotTargets interface {
	ResolveSourceSnapshot(context.Context, targets.SourceSnapshotTarget) (targets.SourceSnapshotResolution, error)
}

func (s ContextInvestigation) resolveSourceSnapshot(ctx context.Context, selected *planning.SourceSnapshotContext) (targets.PodResolution, *targets.SourceSnapshotResolution, error) {
	if selected == nil || selected.SourceTarget == nil || !selected.SourceTarget.Valid() || selected.SourceTarget.SourceID != selected.Request.SourceID || selected.SourceTarget.Fence != selected.Request.Fence || selected.SourceTarget.BindingDigest != [32]byte(selected.Request.SourceBindingDigest) {
		return targets.PodResolution{}, nil, previewFailure("snapshot/source-reference", value.ErrChanged)
	}
	resolver, ok := s.Targets.(SourceSnapshotTargets)
	if !ok {
		return targets.PodResolution{}, nil, value.ErrUnavailable
	}
	observed, err := resolver.ResolveSourceSnapshot(ctx, *selected.SourceTarget)
	if err != nil {
		return targets.PodResolution{}, nil, err
	}
	if !observed.Valid(s.Now()) || observed.Original != *selected.SourceTarget {
		return targets.PodResolution{}, nil, previewFailure("snapshot/source-observation", value.ErrChanged)
	}
	routing := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: observed.Original.Request, Pin: observed.Original.Pin}
	return routing, &observed, nil
}
func snapshotFactsTargetValid(f contextFacts, now time.Time) bool {
	if source := f.snapshotSource; source != nil {
		return source.Valid(now) && source.Original.Request == f.target.Request && source.Original.Pin == f.target.Pin && f.target.PodResourceVersion == "" && f.target.WorkloadResourceVersion == "" && f.target.ObservedAt.IsZero() && f.target.FreshUntil.IsZero()
	}
	return f.target.Valid(now)
}

func snapshotFactsTargetUntil(f contextFacts) time.Time {
	if f.snapshotSource != nil {
		return f.snapshotSource.FreshUntil
	}
	return f.target.FreshUntil
}
