package capture

import (
	"context"
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
	RootID, InstallationID string
	Reader                 ContextProgressReader
	Recovery               fleetapp.RecoveryReader
	Navigation             ContextCaseNavigation
	Now                    func() time.Time
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
	p, err := s.Reader.ReadContextProgress(ctx, value.ProgressQuery{RootID: s.RootID, CaptureID: captureID, Identity: i, Recovery: r})
	if err != nil {
		return zero, err
	}
	if p.CaptureID != captureID || !p.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(identity.Earlier(p.ValidUntil, i.ValidUntil), r.FreshUntil)
	out := value.ContextProgress{CaptureID: p.CaptureID, Revision: p.Revision, Phase: p.Phase, ActionPhase: p.ActionPhase, ReasonCode: p.ReasonCode, CreatedAt: p.CreatedAt, Deadline: p.Deadline}
	if p.Phase == "Pending" || p.Phase == "Running" || p.Phase == "Finalizing" {
		out.RetryAfterSeconds = 2
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
	out.ValidUntil = until
	return out, nil
}
