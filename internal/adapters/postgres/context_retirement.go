package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextRetirementReads is an internal C15 SELECT-only dependency diagnostic.
// A caller cannot turn these facts into a release, refund or public disclosure.
// Missing execution history and any retained download row remain blockers.
type ContextRetirementReads struct {
	ledger *Ledger
	root   string
}

var _ app.ContextRetirementReader = (*ContextRetirementReads)(nil)

func NewContextRetirementReads(ctx context.Context, pool *pgxpool.Pool, root string) (*ContextRetirementReads, error) {
	if !authorization.UUID(root) {
		return nil, app.ErrUnavailable
	}
	ledger, err := New(ctx, pool)
	if err != nil {
		return nil, app.ErrUnavailable
	}
	return &ContextRetirementReads{ledger: ledger, root: root}, nil
}
func (s *ContextRetirementReads) ContextRetirementDependencies(ctx context.Context, captureID string) (app.ContextRetirementDependencies, error) {
	var out app.ContextRetirementDependencies
	if s == nil || s.ledger == nil || !authorization.UUID(captureID) {
		return out, app.ErrUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ObserveContextRetirementDependencies(ctx, custodydb.ObserveContextRetirementDependenciesParams{RootID: id(s.root), ID: id(captureID)})
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		out = app.ContextRetirementDependencies{ObservedAt: now.Time, CustodyDeleted: row.CustodyState == "deleted", IntentAuditPending: !row.IntentAcknowledgedAt.Valid, VerificationAuditPending: row.VerificationAuditPending, ExecutionUnresolved: row.ExecutionUnresolved, RetainedCopyReceipts: row.RetainedCopyReceipts, DownloadDependents: row.DownloadDependents, RetentionAuditPending: row.RetentionAuditPending, RetentionCatchupPending: row.RetentionCatchupPending}
		return ctx.Err()
	})
	if err != nil {
		return app.ContextRetirementDependencies{}, app.ErrUnavailable
	}
	return out, nil
}
