package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

var _ capacity.StorageBacking = (*Ledger)(nil)

// ProvisionAllocation is a configuration-reconciliation facet. There is no
// public SQL permission/configuration API. Existing allocations cannot move or
// shrink through this initial insert-only path; reconciliation is still pending.
func (l *Ledger) ProvisionAllocation(ctx context.Context, a capacity.StorageAllocation) error {
	if (artifact.Location{ClusterID: a.ID, ArtifactID: a.PoolID, AttemptID: a.ScopeID}).Validate() != nil || a.PoolRevision < 1 || a.Revision < 1 || a.Bytes < 0 || a.Objects < 0 || a.ValidUntil.IsZero() || a.ValidUntil.Nanosecond()%1000 != 0 || (a.ServiceClass != "context" && a.ServiceClass != "evidence") {
		return artifact.ErrInvalid
	}
	return l.transaction(ctx, func(q *custodydb.Queries) error {
		p, err := q.LockPool(ctx, id(a.PoolID))
		if err != nil {
			return err
		}
		old, err := q.LockAllocation(ctx, id(a.ID))
		if err == nil {
			if old.PoolID != p.ID || old.ScopeID != id(a.ScopeID) || old.ServiceClass != a.ServiceClass || old.Revision != a.Revision || old.ByteLimit != a.Bytes || old.ObjectLimit != a.Objects || !old.ValidUntil.Time.Equal(a.ValidUntil) {
				return privacy.ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if p.Revision != a.PoolRevision {
			return privacy.ErrFence
		}
		if p.Paused || !n.Time.Before(p.ValidUntil.Time) || !n.Time.Before(a.ValidUntil) || a.ValidUntil.After(p.ValidUntil.Time) {
			return privacy.ErrExpired
		}
		changed, err := q.BackAllocation(ctx, custodydb.BackAllocationParams{ID: p.ID, AllocatedBytes: a.Bytes, AllocatedObjects: a.Objects})
		if err != nil {
			return err
		}
		if changed != 1 {
			return privacy.ErrCapacity
		}
		if err = q.InsertAllocation(ctx, custodydb.InsertAllocationParams{ID: id(a.ID), PoolID: p.ID, ScopeID: id(a.ScopeID), ServiceClass: a.ServiceClass, Revision: a.Revision, ValidUntil: ts(a.ValidUntil), ByteLimit: a.Bytes, ObjectLimit: a.Objects}); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(p.ValidUntil.Time) || !n.Time.Before(a.ValidUntil) {
			return privacy.ErrExpired
		}
		return nil
	})
}
