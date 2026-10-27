package capture

import (
	"context"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// ReviewedAdmissionTransaction cannot be satisfied by the earlier low-level
// admission port: durable preview revalidation belongs inside its SQL lock.
type ReviewedAdmissionTransaction interface {
	AdmitReviewedContext(context.Context, string, value.Admission) (value.Accepted, error)
}

// ContextRequestResolution commits accepted-or-closed under the same root lock
// as admission. Unknown COMMIT is an error; it never implies non-admission.
type ContextRequestResolution interface {
	ResolveOrCloseContextRequest(context.Context, value.ReplayQuery) (value.ContextRequestDisposition, error)
}

// ResolveContextRequest may resolve or fence the original request while new
// acquisition is unavailable. No target discovery, capability or storage port
// is needed. Current caller/recovery/scope and final metadata bounds still apply.
func (s ContextInvestigation) ResolveContextRequest(ctx context.Context, source identities.CurrentIdentity, previewID, key string) (value.ContextRequestDisposition, error) {
	var zero value.ContextRequestDisposition
	if ctx == nil || source == nil || s.Now == nil || s.Resolution == nil || s.Recovery == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(previewID) || !identity.Text(key, 128) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := s.Now()
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return zero, value.ErrDenied
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return zero, err
	}
	if s.Reviews != nil {
		// A revoked exec right must not resolve the request: the caller's
		// recorded decision-time reviews of the preview's Pod are repeated
		// before the resolution re-evaluates eligibility (ADR-245).
		_ = s.Reviews.ReviewPreview(ctx, i, previewID)
	}
	d, err := s.Resolution.ResolveOrCloseContextRequest(ctx, value.ReplayQuery{RootID: s.RootID, PreviewID: previewID, IdempotencyKey: key, SubmissionDigest: ContextRequestDigest(previewID), Identity: i, Recovery: recovery})
	if err != nil {
		return zero, err
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !recovery.Valid(s.Now()) || s.Now().Before(started) {
		return zero, value.ErrDenied
	}
	d.ValidUntil = identity.Earlier(d.ValidUntil, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	if !d.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	if d.State == value.RequestAccepted && !acceptedContext(*d.Accepted, ContextRequestDigest(previewID)) {
		return zero, value.ErrUnavailable
	}
	return d, nil
}
