package capture

import (
	"context"
	"slices"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextHistoryReader reads accepted-capture history under current SQL
// permissions after recovery and permission locks. It never reads evidence.
type ContextHistoryReader interface {
	ListCaptureHistory(context.Context, value.HistoryQuery) (value.HistoryPage, error)
	ReadCaptureSettings(context.Context, value.SettingsQuery) (value.CaptureSettings, error)
}

// ContextRepeatPreview is the normal preview with the original workload
// identity pinned (ContextInvestigation.PreviewRepeat).
type ContextRepeatPreview interface {
	PreviewRepeat(context.Context, identities.CurrentIdentity, value.ContextIntent, authorization.Target) (ContextPreviewResult, error)
}

// ContextHistoryService serves "Recent captures" and "Collect again"
// (ADR-236, REQ-HIS-001/002/004). Listing resolves the named workload to its
// current identity first, so a recreated workload never inherits history.
// A repeat restores only the accepted target, preset and requested retention
// and then runs the ordinary preview: no old grant, audience, reason, pod or
// assessment is reused.
type ContextHistoryService struct {
	RootID, InstallationID string
	Keys                   HistoryKeys
	Reader                 ContextHistoryReader
	Targets                ContextTargets
	// Workloads resolves a Deployment or StatefulSet to its current object
	// identity without requiring a Pod (the regional workload LIST of
	// ADR-228), so history of a workload scaled to zero stays readable.
	Workloads RestartObserver
	Previews  ContextRepeatPreview
	Recovery  fleetapp.RecoveryReader
	Now       func() time.Time
}

func (s ContextHistoryService) configured() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.Reader != nil && s.Targets != nil && s.Workloads != nil && s.Previews != nil && s.Recovery != nil && s.Now != nil
}

// workload resolves the named target to its current object identity: a
// Deployment or StatefulSet without needing any Pod, an explicit Pod as
// itself. Stored history must not depend on the workload's live Pods.
func (s ContextHistoryService) workload(ctx context.Context, ref targets.WorkloadRequest) (authorization.Target, time.Time, error) {
	if ref.Kind == "Pod" {
		p, err := s.Targets.ResolveWorkload(ctx, ref)
		if err != nil {
			return authorization.Target{}, time.Time{}, err
		}
		if !p.Valid(s.Now()) || p.Request.ClusterID != ref.ClusterID || p.Request.Namespace.Name != ref.Namespace || p.Request.Workload.Kind != "Pod" || p.Request.PodName != ref.Name {
			return authorization.Target{}, time.Time{}, value.ErrUnavailable
		}
		return p.Target(), p.FreshUntil, nil
	}
	o, err := s.Workloads.ObserveWorkloadRestarts(ctx, targets.RestartRequest{WorkloadRequest: ref})
	if err != nil {
		return authorization.Target{}, time.Time{}, err
	}
	if !o.Valid(s.Now()) || o.ClusterID != ref.ClusterID || o.Namespace.Name != ref.Namespace || o.Workload.Kind != ref.Kind || o.Workload.Name != ref.Name || o.Probe != "" || o.Alert {
		return authorization.Target{}, time.Time{}, value.ErrUnavailable
	}
	return authorization.WorkloadScope(o.ClusterID, o.Namespace.UID, o.Workload.UID), o.FreshUntil, nil
}

func (s ContextHistoryService) begin(ctx context.Context, source identities.CurrentIdentity) (identity.Identity, error) {
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return identity.Identity{}, value.ErrDenied
	}
	i.Groups, i.Scopes = slices.Clone(i.Groups), slices.Clone(i.Scopes)
	return i, nil
}

func (s ContextHistoryService) finish(ctx context.Context, source identities.CurrentIdentity, i identity.Identity, until time.Time) (time.Time, error) {
	fresh, err := source.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) || ctx.Err() != nil {
		return time.Time{}, value.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if !s.Now().Before(until) {
		return time.Time{}, value.ErrUnavailable
	}
	return until, nil
}

// List returns one page of the named workload's history visible to the caller.
func (s ContextHistoryService) List(ctx context.Context, source identities.CurrentIdentity, ref targets.WorkloadRequest, origins []value.HistoryOrigin, after *value.HistoryCursor, limit int) (value.HistoryPage, error) {
	var zero value.HistoryPage
	if !s.configured() || ctx == nil || source == nil {
		return zero, value.ErrUnavailable
	}
	if !ref.Valid() {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.begin(ctx, source)
	if err != nil {
		return zero, err
	}
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil || r.InstallationID != s.InstallationID || !r.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	// The name resolves to the workload's current UIDs before any history
	// lookup; an absent or unauthorized workload is the uniform refusal.
	target, observedUntil, err := s.workload(ctx, ref)
	if err != nil {
		return zero, err
	}
	selector := value.HistorySelector{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadKind: ref.Kind, WorkloadUID: target.WorkloadUID}
	if ref.Kind == "Pod" {
		selector.WorkloadUID = target.PodUID
	}
	var selectorKey artifact.Digest
	if s.Keys != nil {
		selectorKey, err = HistorySelectorKey(s.Keys, s.RootID, selector)
		if err != nil {
			return zero, err
		}
	}
	snapshot := s.Now().UTC().Truncate(time.Microsecond)
	if after != nil && !after.SnapshotBefore.IsZero() {
		snapshot = after.SnapshotBefore
	}
	page, err := s.Reader.ListCaptureHistory(ctx, value.HistoryQuery{SelectorKey: selectorKey, SnapshotBefore: snapshot, RootID: s.RootID, Target: target, Origins: origins, After: after, Limit: limit, Identity: i, Recovery: r})
	if err != nil {
		return zero, err
	}
	page.Target = target
	until := identity.Earlier(identity.Earlier(page.ValidUntil, i.ValidUntil), identity.Earlier(r.FreshUntil, observedUntil))
	if page.ValidUntil, err = s.finish(ctx, source, i, until); err != nil {
		return zero, err
	}
	return page, nil
}

// Settings returns the repeatable settings of one visible history entry.
func (s ContextHistoryService) Settings(ctx context.Context, source identities.CurrentIdentity, captureID string) (value.CaptureSettings, error) {
	var zero value.CaptureSettings
	if !s.configured() || ctx == nil || source == nil {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(captureID) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.begin(ctx, source)
	if err != nil {
		return zero, err
	}
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil || r.InstallationID != s.InstallationID || !r.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	settings, err := s.Reader.ReadCaptureSettings(ctx, value.SettingsQuery{RootID: s.RootID, CaptureID: captureID, Identity: i, Recovery: r})
	if err != nil {
		return zero, err
	}
	if settings.CaptureID != captureID {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(identity.Earlier(settings.ValidUntil, i.ValidUntil), r.FreshUntil)
	if settings.ValidUntil, err = s.finish(ctx, source, i, until); err != nil {
		return zero, err
	}
	return settings, nil
}

// PreviewRepeat prepares "Collect again": the normal preview of the original
// named workload with its original requested retention. Reading the settings
// needs history visibility; the preview itself needs current collection
// eligibility, capacity, retention and every other check of a new preview.
// An optional sharing instruction (ADR-235) is the caller's new one; the
// original capture's sharing is never restored.
func (s ContextHistoryService) PreviewRepeat(ctx context.Context, source identities.CurrentIdentity, captureID string, sharing *value.ContextSharing) (ContextPreviewResult, value.CaptureSettings, error) {
	return s.PreviewEditedRepeat(ctx, source, captureID, sharing, value.HistoryRepeatEdits{})
}

func (s ContextHistoryService) PreviewEditedRepeat(ctx context.Context, source identities.CurrentIdentity, captureID string, sharing *value.ContextSharing, edits value.HistoryRepeatEdits) (ContextPreviewResult, value.CaptureSettings, error) {
	settings, err := s.Settings(ctx, source, captureID)
	if err != nil {
		return ContextPreviewResult{}, value.CaptureSettings{}, err
	}
	originalTarget := targets.WorkloadRequest{ClusterID: settings.ClusterID, Namespace: settings.Namespace, Kind: settings.WorkloadKind, Name: settings.WorkloadName}
	if edits.Target != nil && *edits.Target != originalTarget {
		return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrInvalid
	}
	if edits.Selection != "" && edits.Selection != "currentEligiblePod" {
		return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrInvalid
	}
	if settings.Selection == "triggeringPod" && edits.Selection != "currentEligiblePod" {
		return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrHistorySelectionRequired
	}
	intent := value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: settings.ClusterID, Namespace: settings.Namespace, Kind: settings.WorkloadKind, Name: settings.WorkloadName}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: settings.RequestedSeconds, Sharing: sharing}
	if settings.Composition != nil {
		intent.Diagnostic = ""
		intent.Composition = settings.Composition.Clone()
	}
	if edits.Composition != nil {
		if settings.Composition == nil {
			return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrInvalid
		}
		intent.Composition = edits.Composition.Clone()
	}
	if edits.RequestedSeconds > 0 {
		intent.RequestedSeconds = edits.RequestedSeconds
	}
	intent.RepeatedFrom = &value.HistoryLineage{CaptureID: captureID, ExpiresAt: settings.ExpiresAt}
	if settings.Composition != nil {
		previews, ok := s.Previews.(interface {
			PreviewCompositionRepeat(context.Context, identities.CurrentIdentity, value.ContextIntent, authorization.Target) (RecorderPreviewResult, error)
		})
		if !ok {
			return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrSettingsUnavailable
		}
		recorder, e := previews.PreviewCompositionRepeat(ctx, source, intent, authorization.Target{ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, WorkloadUID: settings.WorkloadUID, PodUID: settings.ExplicitPodUID})
		if e != nil {
			return ContextPreviewResult{}, value.CaptureSettings{}, e
		}
		if !historyDependenciesMatch(settings, recorder.CollectorImageDigest, recorder.ProjectionDigest, recorder.Plan.Profiles) || !historyFiltersMatch(settings.FrozenFilters, recorder.Plan.CanonicalScope, edits.Composition != nil) {
			return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrProfileChanged
		}
		return ContextPreviewResult{Preview: recorder.Preview, ValidUntil: recorder.ValidUntil, Recorder: &recorder}, settings, nil
	}
	result, err := s.Previews.PreviewRepeat(ctx, source, intent, authorization.Target{ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, WorkloadUID: settings.WorkloadUID, PodUID: settings.ExplicitPodUID})
	if err != nil {
		return ContextPreviewResult{}, value.CaptureSettings{}, err
	}
	if !historyDependenciesMatch(settings, result.CollectorImageDigest, result.ProjectionDigest, nil) {
		return ContextPreviewResult{}, value.CaptureSettings{}, value.ErrProfileChanged
	}
	return result, settings, nil
}
