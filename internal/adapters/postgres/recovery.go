package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
)

// currentTrust reads the installation's static fleet trust row
// (ADR-330 D13). A missing row means setup has not run.
func currentTrust(ctx context.Context, q *custodydb.Queries, installation string) (custodydb.FleetCurrentTrust, error) {
	return q.ReadFleetTrust(ctx, id(installation))
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
