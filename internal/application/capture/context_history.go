package capture

import (
	"context"
	"slices"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
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
	Reader                 ContextHistoryReader
	Targets                ContextTargets
	Previews               ContextRepeatPreview
	Recovery               fleetapp.RecoveryReader
	Now                    func() time.Time
}

func (s ContextHistoryService) configured() bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && s.Reader != nil && s.Targets != nil && s.Previews != nil && s.Recovery != nil && s.Now != nil
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
	target, err := s.Targets.ResolveWorkload(ctx, ref)
	if err != nil {
		return zero, err
	}
	if !target.Valid(s.Now()) || target.Request.ClusterID != ref.ClusterID || target.Request.Namespace.Name != ref.Namespace || target.Request.Workload.Kind != ref.Kind || target.Request.Workload.Name != ref.Name {
		return zero, value.ErrUnavailable
	}
	page, err := s.Reader.ListCaptureHistory(ctx, value.HistoryQuery{RootID: s.RootID, Target: target.Target(), Origins: origins, After: after, Limit: limit, Identity: i, Recovery: r})
	if err != nil {
		return zero, err
	}
	until := identity.Earlier(identity.Earlier(page.ValidUntil, i.ValidUntil), identity.Earlier(r.FreshUntil, target.FreshUntil))
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
	settings, err := s.Settings(ctx, source, captureID)
	if err != nil {
		return ContextPreviewResult{}, value.CaptureSettings{}, err
	}
	intent := value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: settings.ClusterID, Namespace: settings.Namespace, Kind: settings.WorkloadKind, Name: settings.WorkloadName}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: settings.RequestedSeconds, Sharing: sharing}
	result, err := s.Previews.PreviewRepeat(ctx, source, intent, authorization.Target{ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, WorkloadUID: settings.WorkloadUID})
	if err != nil {
		return ContextPreviewResult{}, value.CaptureSettings{}, err
	}
	return result, settings, nil
}
