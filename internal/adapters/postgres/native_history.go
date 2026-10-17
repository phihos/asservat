package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// NativeHistory is separately credentialed installation/cleanup work. Runtime
// native claim/key writers cannot create backing or erase uncertain charges.
// Qualification facts are protected producer input, never estimated here.
type NativeHistory struct {
	ledger *Ledger
	root   string
}

func NewNativeHistory(ctx context.Context, pool *pgxpool.Pool, root string) (*NativeHistory, error) {
	if !value.UUID(root) {
		return nil, artifact.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &NativeHistory{l, root}, nil
}
func (s *NativeHistory) InstallNativeBacking(ctx context.Context, b value.NativeBacking) error {
	if s == nil || ctx == nil || !b.Valid() || b.RootID != s.root || !time.Now().Before(b.ValidUntil) {
		return artifact.ErrInvalid
	}
	encoded, e := json.Marshal(b)
	if e != nil || len(encoded) > 4096 {
		return artifact.ErrInvalid
	}
	return custodydb.New(s.ledger.pool).InsertNativeBacking(ctx, custodydb.InsertNativeBackingParams{AllocationID: id(b.AllocationID), RootID: id(b.RootID), PolicyJson: encoded, RowsLimit: b.Rows, KeysLimit: b.Keys, TransitionsPerRow: b.TransitionsPerRow, BackupHorizonSeconds: b.BackupHorizonSeconds, CleanupSeconds: b.CleanupSeconds, ValidUntil: ts(b.ValidUntil), RetireBy: ts(b.RetireBy)})
}

// Positive stored worker retirement is checked by SQL; timeout/404/native lease
// expiry cannot claim quiescence. Both normal and late cleanup remain bounded.
func (s *NativeHistory) RetireNativeOwner(ctx context.Context, worker string) error {
	if s == nil || ctx == nil || !value.UUID(worker) {
		return artifact.ErrInvalid
	}
	_, e := custodydb.New(s.ledger.pool).RetireNativeOwner(ctx, custodydb.RetireNativeOwnerParams{WorkerID: id(worker), RootID: id(s.root)})
	return e
}
func (s *NativeHistory) PurgeRetiredNativeOwner(ctx context.Context, worker string) error {
	if s == nil || ctx == nil || !value.UUID(worker) {
		return artifact.ErrInvalid
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, e := q.DeleteNativeKeys(ctx, custodydb.DeleteNativeKeysParams{WorkerID: id(worker), RootID: id(s.root)}); e != nil {
			return e
		}
		_, e := q.DeleteNativeOwner(ctx, custodydb.DeleteNativeOwnerParams{WorkerID: id(worker), RootID: id(s.root)})
		return e
	})
}
func (s *NativeHistory) RetireNativeBacking(ctx context.Context, allocation string) error {
	if s == nil || ctx == nil || !value.UUID(allocation) {
		return artifact.ErrInvalid
	}
	_, e := custodydb.New(s.ledger.pool).DeleteNativeBacking(ctx, custodydb.DeleteNativeBackingParams{AllocationID: id(allocation), RootID: id(s.root)})
	return e
}
