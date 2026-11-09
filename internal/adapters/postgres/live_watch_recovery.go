package postgres

import (
	"context"
	"fmt"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/authorization"
	v "asservat.local/asservat/internal/domain/live"
)

var _ liveapp.RecoveryLedger = (*LiveWatches)(nil)

func (s *LiveWatches) ReadLiveControl(ctx context.Context, principal [32]byte, watch string) (liveapp.Control, error) {
	zero := liveapp.Control{}
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || principal == ([32]byte{}) || !authorization.UUID(watch) {
		return zero, fmt.Errorf("%w: live_watch_recovery:read-input", v.ErrInvalid)
	}
	var raw []byte
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		raw, err = q.ReadLiveControl(ctx, custodydb.ReadLiveControlParams{RootID: id(s.root), PrincipalKey: principal[:], WatchID: id(watch)})
		return err
	})
	if err != nil {
		return zero, liveError(err)
	}
	control, err := decodeLive(raw)
	if err != nil || control.ID != watch || control.PrincipalKey != principal {
		return zero, fmt.Errorf("%w: live_watch_recovery:read-control", v.ErrUnavailable)
	}
	return control, nil
}

func (s *LiveWatches) CloseLiveControl(ctx context.Context, control liveapp.Control) (liveapp.Control, error) {
	zero := liveapp.Control{}
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || control.PrincipalKey == ([32]byte{}) || !authorization.UUID(control.ID) || !authorization.UUID(control.OwnerID) || !authorization.UUID(control.Fence) || control.Revision < 1 {
		return zero, fmt.Errorf("%w: live_watch_recovery:close-input", v.ErrInvalid)
	}
	var raw []byte
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		raw, err = q.CloseLiveControl(ctx, custodydb.CloseLiveControlParams{RootID: id(s.root), PrincipalKey: control.PrincipalKey[:], WatchID: id(control.ID), ExpectedRevision: control.Revision, Fence: id(control.Fence)})
		return liveSQLError(err)
	})
	if err != nil {
		return zero, liveError(err)
	}
	closed, err := decodeLive(raw)
	if err != nil || closed.ID != control.ID || closed.OwnerID != control.OwnerID || closed.PrincipalKey != control.PrincipalKey || closed.Fence != control.Fence || closed.Revision != control.Revision {
		return zero, fmt.Errorf("%w: live_watch_recovery:close-control", v.ErrUnavailable)
	}
	return closed, nil
}
