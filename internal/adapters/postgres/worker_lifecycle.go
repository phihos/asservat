package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewScopedWorkerOperationLifecycles selects the installed worker's closed
// capture/normal/resolution compartment. It shares one bounded scheduler and
// the existing row state machine, with each immutable row's original policy.
func NewScopedWorkerOperationLifecycles(ctx context.Context, pool *pgxpool.Pool, root, installation, store string, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	s, err := NewScopedCaptureOperationLifecycles(ctx, pool, root, installation, store, recovery)
	if err != nil {
		return nil, err
	}
	s.capture, s.worker = false, true
	return s, nil
}

func workerCleanupLane(lane string) bool {
	return lane == "capture" || lane == "normal" || lane == "resolution"
}

func (s *OperationLifecycles) acceptsLane(lane string) bool {
	return s != nil && s.journal != nil && (s.worker && workerCleanupLane(lane) || !s.worker && lane == s.journal.lane)
}

func (s captureLifecycleScope) matchesWorker(in value.OperationIntent) bool {
	if !s.valid() || !in.Valid() || in.Lifecycle == nil || in.RootID != s.root {
		return false
	}
	p := in.Lifecycle.Policy
	return workerCleanupLane(p.Lane) && p.Lane == value.OperationLane(in.Name) && p.CertificateVerificationBacked() &&
		p.RootID == s.root && p.InstallationID == s.installation && p.StoreID == s.store
}

type workerLifecycleQueries struct{ captureLifecycleQueries }

func (q workerLifecycleQueries) DueOperationAuditHistory(ctx context.Context, arg custodydb.DueOperationAuditHistoryParams) ([]custodydb.DueOperationAuditHistoryRow, error) {
	rows, err := q.Queries.WorkerDueOperationAuditHistory(ctx, arg.RootID)
	if err != nil || len(rows) > 16 {
		return nil, app.ErrUnavailable
	}
	out := make([]custodydb.DueOperationAuditHistoryRow, len(rows))
	for i, row := range rows {
		out[i] = custodydb.DueOperationAuditHistoryRow(row)
	}
	return out, nil
}
