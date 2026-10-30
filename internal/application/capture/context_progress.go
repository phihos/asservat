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
)

type ContextProgressReader interface {
	ReadContextProgress(context.Context, value.ProgressQuery) (value.ContextProgressObservation, error)
}

// ContextDeadlineObserver records elapsed original deadlines in bounded SQL
// pages. It cannot start/cancel work, release charges or publish evidence.
type ContextDeadlineObserver interface {
	ObserveOverdueContextCaptures(context.Context, int) (int64, error)
}

type ContextCaseLink struct {
	CaseID                 string
	ObservedAt, ValidUntil time.Time
}

// ContextCaseNavigation independently checks current case access. A captured
// case UUID or historical publication is insufficient. Omission fails closed
// for links without withholding otherwise authorized collection status.
type ContextCaseNavigation interface {
	ContextCaseNavigation(context.Context, identities.CurrentIdentity, value.ContextProgressObservation) (ContextCaseLink, error)
}

type ContextProgressService struct {
	Reasons                CaptureReasonReader
	RootID, InstallationID string
	Reader                 ContextProgressReader
	Recovery               fleetapp.RecoveryReader
	Navigation             ContextCaseNavigation
	// Shares reads capture-time shares (ADR-235). Without it, a capture
	// carrying a sharing instruction is reported unavailable.
	Shares CaptureShareReader
	// Reviews repeats the caller's recorded decision-time reviews of the
	// capture's Pod before the status read (ADR-245); nil disables them.
	Reviews ContextCaptureReviews
	Now     func() time.Time
}

// ContextCaptureReviews repeats a principal's recorded decision-time reviews
// of one capture's Pod (ADR-245). It returns nothing of the capture.
type ContextCaptureReviews interface {
	ReviewCapture(context.Context, identity.Identity, string) error
}

func (s ContextProgressService) Get(ctx context.Context, source identities.CurrentIdentity, captureID string) (value.ContextProgress, error) {
	var zero value.ContextProgress
	if ctx == nil || source == nil || s.Reader == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(captureID) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil || r.InstallationID != s.InstallationID || !r.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	if s.Reviews != nil {
		_ = s.Reviews.ReviewCapture(ctx, i, captureID)
	}
	p, err := s.Reader.ReadContextProgress(ctx, value.ProgressQuery{RootID: s.RootID, CaptureID: captureID, Identity: i, Recovery: r})
	if err != nil {
		return zero, err
	}
	if p.CaptureID != captureID || !p.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(identity.Earlier(p.ValidUntil, i.ValidUntil), r.FreshUntil)
	out := value.ContextProgress{Actions: slices.Clone(p.Actions), CanCancel: p.CanCancel, CancellationRequested: p.CancellationRequested, Operation: p.Operation, ActionID: p.ActionID, RepeatedFrom: p.RepeatedFrom, HistoryState: p.HistoryState, CaptureID: p.CaptureID, Revision: p.Revision, Phase: p.Phase, ActionPhase: p.ActionPhase, ReasonCode: p.ReasonCode, CreatedAt: p.CreatedAt, Deadline: p.Deadline}
	if p.ReasonMetadata != nil {
		out.ReasonState = "unavailable"
		if s.Reasons != nil && p.ReasonMetadata.Valid() {
			text, reasonErr := s.Reasons.ReadCaptureReason(ctx, *p.ReasonMetadata)
			if reasonErr == nil && validOptionalReason(&text) {
				out.Reason, out.ReasonState = &text, "available"
			}
		}
	}
	if p.Phase == "Pending" || p.Phase == "Running" || p.Phase == "Finalizing" {
		out.RetryAfterSeconds = 2
	}
	if out.Sharing, err = sharingStatus(ctx, s.Shares, p); err != nil {
		return zero, err
	}
	if s.Navigation != nil {
		link, err := s.Navigation.ContextCaseNavigation(ctx, source, p)
		if err == nil && link.CaseID == p.CandidateCaseID && identity.Fresh(link.ObservedAt, link.ValidUntil, s.Now(), 5*time.Second) {
			out.CaseID = link.CaseID
			until = identity.Earlier(until, link.ValidUntil)
		}
	}
	fresh, err := source.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || !fresh.Valid(s.Now()) || !s.Now().Before(until) || !p.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	if out.RepeatedFrom != nil && !out.RepeatedFrom.Valid(s.Now()) {
		out.RepeatedFrom = nil
	}
	out.ValidUntil = until
	return out, nil
}
