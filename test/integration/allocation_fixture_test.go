package integration

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testAllocation is one directly provisioned custody allocation for custody
// tests whose subject is not capacity enrollment.
type testAllocation struct {
	ID, PoolID, ScopeID, ServiceClass      string
	PoolRevision, Revision, Bytes, Objects int64
	ValidUntil                             time.Time
}

// provisionAllocation backs a from its pool, or returns privacy.ErrCapacity.
func provisionAllocation(ctx context.Context, admin *pgxpool.Pool, a testAllocation) error {
	return pgx.BeginFunc(ctx, admin, func(tx pgx.Tx) error {
		c, err := tx.Exec(ctx, `UPDATE custody_pool SET allocated_bytes=allocated_bytes+$2,allocated_objects=allocated_objects+$3 WHERE id=$1 AND revision=$4 AND $2<=byte_limit-allocated_bytes AND $3<=object_limit-allocated_objects`, a.PoolID, a.Bytes, a.Objects, a.PoolRevision)
		if err != nil {
			return err
		}
		if c.RowsAffected() != 1 {
			return privacy.ErrCapacity
		}
		_, err = tx.Exec(ctx, `INSERT INTO custody_allocation(id,pool_id,scope_id,service_class,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, a.ID, a.PoolID, a.ScopeID, a.ServiceClass, a.Revision, a.ValidUntil, a.Bytes, a.Objects)
		return err
	})
}
