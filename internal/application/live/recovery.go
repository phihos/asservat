package live

import (
	"context"
	"fmt"

	"asservat.local/asservat/internal/domain/authorization"
	v "asservat.local/asservat/internal/domain/live"
)

type RecoveryLedger interface {
	ReadLiveControl(context.Context, [32]byte, string) (Control, error)
	CloseLiveControl(context.Context, Control) (Control, error)
}

func recoveredControlValid(c Control) bool {
	return authorization.UUID(c.ID) && authorization.UUID(c.OwnerID) && authorization.UUID(c.Fence) && c.Revision >= 1 && c.OutputLimit >= 1 && c.Spent >= 0 && c.Spent <= c.OutputLimit && c.BytesPerSecond >= 1 && !c.AcceptedAt.IsZero() && c.ExpiresAt.After(c.AcceptedAt) && c.IdleUntil.After(c.AcceptedAt) && !c.IdleUntil.After(c.ExpiresAt)
}

func sameRecoveredControl(a, b Control) bool {
	a.State, b.State = "", ""
	return a == b
}

func (s *Service) recoverRead(ctx context.Context, current CurrentIdentity, r v.Read, keys RouteKeys, ownerID string) (v.Batch, error) {
	zero := v.Batch{}
	i, err := s.actor(ctx, current)
	if err != nil || i.Principal != keys.Actor || i.Policy != keys.Policy {
		return zero, fmt.Errorf("%w: recovery:actor", v.ErrDenied)
	}
	recovery, ok := s.ledger.(RecoveryLedger)
	if !ok {
		return zero, fmt.Errorf("%w: recovery:ledger", v.ErrUnavailable)
	}
	control, err := recovery.ReadLiveControl(ctx, keys.PrincipalKey, r.ID)
	if err != nil {
		return zero, err
	}
	if !recoveredControlValid(control) || control.ID != r.ID || control.OwnerID != ownerID || control.PrincipalKey != keys.PrincipalKey {
		return zero, fmt.Errorf("%w: recovery:control", v.ErrUnavailable)
	}
	end := minTime(minTime(i.ValidUntil, keys.Until), minTime(control.ExpiresAt, control.IdleUntil))
	now := s.cfg.Now()
	if ctx.Err() != nil || !now.Before(end) {
		return zero, fmt.Errorf("%w: recovery:expired", v.ErrDenied)
	}
	st := session{watch: v.Watch{ID: control.ID, Revision: control.Revision, State: control.State, AcceptedAt: control.AcceptedAt, ExpiresAt: control.ExpiresAt, IdleUntil: control.IdleUntil}, control: control, actor: i.Principal}
	if _, valid := s.cursorPosition(&st, r.Cursor); !valid {
		return zero, fmt.Errorf("%w: recovery:cursor", v.ErrConflict)
	}
	closed, err := recovery.CloseLiveControl(ctx, control)
	if err != nil {
		return zero, err
	}
	if !recoveredControlValid(closed) || !sameRecoveredControl(control, closed) || !v.Terminal(closed.State) {
		return zero, fmt.Errorf("%w: recovery:close", v.ErrUnavailable)
	}
	end = minTime(end, minTime(closed.ExpiresAt, closed.IdleUntil))
	now = s.cfg.Now()
	if ctx.Err() != nil || !now.Before(end) {
		return zero, fmt.Errorf("%w: recovery:final", v.ErrDenied)
	}
	return v.Batch{DisclosureUntil: end, WatchID: closed.ID, Revision: closed.Revision, ID: s.cfg.NewID(), State: closed.State, Rows: []v.Row{}, Sources: []v.SourceStatus{}, Gaps: []v.Gap{{Reason: "reconnect", From: now, Until: now}}, From: now, Until: now, ReceivedAt: now, Spent: closed.Spent, RetryAfter: 1000, Handling: v.Notices()}, nil
}

func (s *Service) BeginRecoveredLocalCommand(ctx context.Context, current CurrentIdentity, r v.Read, keys RouteKeys, ownerID string) (CommandDelivery, error) {
	if s == nil || !r.Valid() || ctx == nil || ctx.Err() != nil || !keys.Actor.Valid() || !keys.Policy.Valid() || !authorization.UUID(ownerID) || !s.cfg.Now().Before(keys.Until) {
		return nil, fmt.Errorf("%w: recovery:input", v.ErrInvalid)
	}
	current = routeBoundIdentity{inner: current, keys: keys, now: s.cfg.Now}
	batch, err := s.recoverRead(ctx, current, r, keys, ownerID)
	if err != nil {
		return nil, err
	}
	until := minTime(keys.Until, batch.DisclosureUntil)
	if end, ok := ctx.Deadline(); ok {
		until = minTime(until, end)
	}
	if !s.cfg.Now().Before(until) || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: recovery:delivery", v.ErrUnavailable)
	}
	owned, cancel := context.WithDeadline(ctx, until)
	return &localCommandDelivery{ctx: owned, cancel: cancel, result: CommandResult{Batch: &batch}, until: until, now: s.cfg.Now}, nil
}
