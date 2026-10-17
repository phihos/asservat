package postgres

import (
	"context"
	"errors"
	"math"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

var _ capacity.ContextControlBacking = (*Ledger)(nil)

func validControlBounds(root string, expected, revision, full, replay int64, until, observed, fresh time.Time) bool {
	return authorization.UUID(root) && expected >= 0 && expected < math.MaxInt64 && revision == expected+1 && full >= 0 && replay >= 0 && !until.IsZero() && until.Nanosecond()%1000 == 0 && observed.Nanosecond()%1000 == 0 && fresh.Nanosecond()%1000 == 0 && identity.Fresh(observed, fresh, observed, 5*time.Second)
}
func controlConfigurationCurrent(now, until, observed, fresh time.Time) bool {
	return now.Before(until) && identity.Fresh(observed, fresh, now, 5*time.Second)
}

// These are protected configuration facets, not public authorization. The
// accepted Kubernetes configuration reconciler must supply these observations;
// this component does not accept that source itself. Updates keep the same
// root/allocation, require the exact previous revision and preserve all spend.
func (l *Ledger) ProvisionContextControlPool(ctx context.Context, in capacity.ContextControlPool) error {
	if l == nil || !validControlBounds(in.RootID, in.ExpectedRevision, in.Revision, in.FullRecords, in.ReplayRecords, in.ValidUntil, in.ObservedAt, in.FreshUntil) {
		return artifact.ErrInvalid
	}
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(in.RootID)); err != nil {
			return err
		}
		old, err := q.LockContextControlPool(ctx, id(in.RootID))
		if err == nil && old.Configured && old.Revision == in.Revision {
			if old.Paused != in.Paused || old.FullLimit != in.FullRecords || old.ReplayLimit != in.ReplayRecords || !old.ValidUntil.Time.Equal(in.ValidUntil) {
				return privacy.ErrConflict
			}
			return ctx.Err() // historical exact replay, never renewed authority
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && old.Revision != in.ExpectedRevision || errors.Is(err, pgx.ErrNoRows) && in.ExpectedRevision != 0 {
			return privacy.ErrConflict
		}
		if err == nil && (old.BackedFull > in.FullRecords || old.BackedReplay > in.ReplayRecords) {
			return privacy.ErrCapacity
		}
		check := func() error {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !controlConfigurationCurrent(now.Time, in.ValidUntil, in.ObservedAt, in.FreshUntil) {
				return privacy.ErrExpired
			}
			return ctx.Err()
		}
		if e := check(); e != nil {
			return e
		}
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = q.InsertContextControlPool(ctx, custodydb.InsertContextControlPoolParams{RootID: id(in.RootID), Revision: in.Revision, ValidUntil: ts(in.ValidUntil), FullLimit: in.FullRecords, ReplayLimit: in.ReplayRecords, Paused: in.Paused})
		} else {
			_, err = q.ConfigureContextControlPool(ctx, custodydb.ConfigureContextControlPoolParams{RootID: id(in.RootID), ExpectedRevision: in.ExpectedRevision, Revision: in.Revision, ValidUntil: ts(in.ValidUntil), FullLimit: in.FullRecords, ReplayLimit: in.ReplayRecords, Paused: in.Paused})
		}
		if err != nil {
			return err
		}
		return check()
	})
}

func (l *Ledger) ProvisionContextControlAllocation(ctx context.Context, in capacity.ContextControlAllocation) error {
	if l == nil || !validControlBounds(in.RootID, in.ExpectedRevision, in.Revision, in.FullRecords, in.ReplayRecords, in.ValidUntil, in.ObservedAt, in.FreshUntil) || !authorization.UUID(in.AllocationID) || in.PoolRevision < 1 {
		return artifact.ErrInvalid
	}
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(in.RootID)); err != nil {
			return err
		}
		pool, err := q.LockContextControlPool(ctx, id(in.RootID))
		if err != nil {
			return err
		}
		storagePool, allocation, err := lockAllocation(ctx, q, in.AllocationID)
		if err != nil {
			return err
		}
		binding, err := q.FindContextControlBinding(ctx, custodydb.FindContextControlBindingParams{RootID: id(in.RootID), AllocationID: id(in.AllocationID)})
		if err != nil {
			return privacy.ErrFence
		}
		old, err := q.LockContextControlAccount(ctx, custodydb.LockContextControlAccountParams{RootID: id(in.RootID), AllocationID: id(in.AllocationID)})
		if err == nil && old.Configured && old.Revision == in.Revision {
			if pool.Revision != in.PoolRevision || old.Paused != in.Paused || old.FullLimit != in.FullRecords || old.ReplayLimit != in.ReplayRecords || !old.ValidUntil.Time.Equal(in.ValidUntil) {
				return privacy.ErrConflict
			}
			return ctx.Err()
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && old.Revision != in.ExpectedRevision || errors.Is(err, pgx.ErrNoRows) && in.ExpectedRevision != 0 {
			return privacy.ErrConflict
		}
		if !pool.Configured || pool.Revision != in.PoolRevision || allocation.ServiceClass != "context" || binding.AllocationID != allocation.ID {
			return privacy.ErrFence
		}
		oldFull, oldReplay := int64(0), int64(0)
		if err == nil {
			oldFull, oldReplay = old.FullLimit, old.ReplayLimit
			if in.FullRecords < old.ChargedFull || in.ReplayRecords < old.ChargedReplay {
				return privacy.ErrCapacity
			}
		}
		if pool.BackedFull < oldFull || pool.BackedReplay < oldReplay || in.FullRecords > pool.FullLimit-(pool.BackedFull-oldFull) || in.ReplayRecords > pool.ReplayLimit-(pool.BackedReplay-oldReplay) {
			return privacy.ErrCapacity
		}
		check := func() error {
			now, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			if !controlConfigurationCurrent(now.Time, in.ValidUntil, in.ObservedAt, in.FreshUntil) || !now.Time.Before(pool.ValidUntil.Time) || storagePool.Paused || allocation.Paused || !now.Time.Before(storagePool.ValidUntil.Time) || !now.Time.Before(allocation.ValidUntil.Time) || !identity.Fresh(binding.ObservedAt.Time, binding.FreshUntil.Time, now.Time, 30*time.Second) {
				return privacy.ErrExpired
			}
			return ctx.Err()
		}
		if e := check(); e != nil {
			return e
		}
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = q.InsertContextControlAccount(ctx, custodydb.InsertContextControlAccountParams{RootID: id(in.RootID), AllocationID: id(in.AllocationID), Revision: in.Revision, ValidUntil: ts(in.ValidUntil), FullLimit: in.FullRecords, ReplayLimit: in.ReplayRecords, Paused: in.Paused})
		} else {
			_, err = q.ConfigureContextControlAccount(ctx, custodydb.ConfigureContextControlAccountParams{RootID: id(in.RootID), AllocationID: id(in.AllocationID), ExpectedRevision: in.ExpectedRevision, Revision: in.Revision, ValidUntil: ts(in.ValidUntil), FullLimit: in.FullRecords, ReplayLimit: in.ReplayRecords, Paused: in.Paused})
		}
		if err != nil {
			return err
		}
		return check()
	})
}

func controlCapacityDeadline(pool custodydb.ContextControlPool, account custodydb.ContextControlAccount, root, allocation string, now time.Time) (time.Time, error) {
	if !pool.Configured || !account.Configured || pool.Paused || account.Paused || pool.RootID != id(root) || account.RootID != pool.RootID || account.AllocationID != id(allocation) || pool.Revision < 1 || account.Revision < 1 || !pool.ValidUntil.Valid || !account.ValidUntil.Valid || !now.Before(pool.ValidUntil.Time) || !now.Before(account.ValidUntil.Time) {
		return time.Time{}, capture.ErrChanged
	}
	if pool.BackedFull > pool.FullLimit || pool.BackedReplay > pool.ReplayLimit || account.FullLimit > pool.BackedFull || account.ReplayLimit > pool.BackedReplay || account.ChargedFull < 0 || account.ChargedReplay < 0 || account.ChargedFull >= account.FullLimit || account.ChargedReplay >= account.ReplayLimit {
		return time.Time{}, capture.ErrCapacity
	}
	return identity.Earlier(pool.ValidUntil.Time, account.ValidUntil.Time), nil
}
func lockContextControlCapacity(ctx context.Context, q *custodydb.Queries, root, allocation string) (time.Time, error) {
	pool, err := q.LockContextControlPool(ctx, id(root))
	if err != nil {
		return time.Time{}, capture.ErrChanged
	}
	account, err := q.LockContextControlAccount(ctx, custodydb.LockContextControlAccountParams{RootID: id(root), AllocationID: id(allocation)})
	if err != nil {
		return time.Time{}, capture.ErrChanged
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return controlCapacityDeadline(pool, account, root, allocation, now.Time)
}
