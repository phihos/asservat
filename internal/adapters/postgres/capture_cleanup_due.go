package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// DueCaptureOperations is a bounded scheduling page over the private filtered
// view. Its IDs grant no deletion authority. The existing lifecycle transaction
// independently rechecks recovery, exact original row/lease and writer closure.
// The caller retains at most one UUID cursor and wraps only after the last page,
// so an unresolved early row cannot starve the rest or create an unbounded list.
func (s *OperationLifecycles) DueCaptureOperations(ctx context.Context, after string) ([]string, error) {
	if s == nil || !s.capture {
		return nil, app.ErrUnavailable
	}
	return s.dueOperations(ctx, after)
}

// DueWorkerOperations uses one UUID cursor and one total sixteen-row page
// across all three compiled worker lanes. A stuck row cannot starve later IDs.
func (s *OperationLifecycles) DueWorkerOperations(ctx context.Context, after string) ([]string, error) {
	if s == nil || !s.worker {
		return nil, app.ErrUnavailable
	}
	return s.dueOperations(ctx, after)
}

func (s *OperationLifecycles) dueOperations(ctx context.Context, after string) ([]string, error) {
	if s == nil || s.journal == nil || s.journal.ledger == nil || s.captureScope.root == "" || ctx == nil || ctx.Err() != nil || after != "" && !authorization.UUID(after) {
		return nil, app.ErrUnavailable
	}
	if after == "" {
		after = "00000000-0000-0000-0000-000000000000"
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	j := s.journal
	var out []string
	err := j.ledger.transaction(call, func(q *custodydb.Queries) error {
		trust, started, err := j.trust(call, q)
		if err != nil {
			return err
		}
		var rows []pgtype.UUID
		if s.worker {
			rows, err = q.WorkerDueOperationLifecycles(call, custodydb.WorkerDueOperationLifecyclesParams{RootID: id(j.root), AfterID: id(after)})
		} else {
			rows, err = q.CaptureDueOperationLifecycles(call, custodydb.CaptureDueOperationLifecyclesParams{RootID: id(j.root), AfterID: id(after)})
		}
		if err != nil || len(rows) > 16 {
			return app.ErrUnavailable
		}
		last := after
		for _, row := range rows {
			key := uid(row)
			if !authorization.UUID(key) || key <= last {
				return app.ErrUnavailable
			}
			out = append(out, key)
			last = key
		}
		return auditCurrent(call, q, trust, started, identity.Earlier(started.Add(5*time.Second), trust.FreshUntil.Time))
	})
	if err != nil || call.Err() != nil {
		return nil, app.ErrUnavailable
	}
	return out, nil
}
