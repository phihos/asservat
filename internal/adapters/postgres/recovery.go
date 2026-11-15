package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// currentTrust reads the installation's fleet trust row and the database
// time, and refuses a suspended or stale row (as the removed recovery guards
// did). It takes no row lock: several callers hold read-only roles, and a
// suspension racing one effect is within the ADR-311 authority reuse window.
func currentTrust(ctx context.Context, q *custodydb.Queries, installation string) (custodydb.FleetCurrentTrust, error) {
	row, err := q.ReadFleetTrust(ctx, id(installation))
	if err != nil {
		return row, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return row, err
	}
	n := now.Time.UTC().Truncate(time.Microsecond)
	if row.Suspended || !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, n, identity.AuthorityRecheckInterval) {
		return row, value.ErrUnavailable
	}
	return row, nil
}

// retentionGuardFor accepts no guard (read, audit and configuration facets)
// or exactly one guard bound to root.
func retentionGuardFor(root string, guards []*RetentionTransactionGuard) (*RetentionTransactionGuard, error) {
	if len(guards) == 0 {
		return nil, nil
	}
	if len(guards) != 1 || guards[0] == nil || guards[0].root != root {
		return nil, artifact.ErrInvalid
	}
	return guards[0], nil
}
