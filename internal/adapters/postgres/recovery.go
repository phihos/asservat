package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
)

// currentTrust reads the installation's static fleet trust row
// (ADR-330 D13). A missing row means setup has not run.
func currentTrust(ctx context.Context, q *custodydb.Queries, installation string) (custodydb.FleetCurrentTrust, error) {
	return q.ReadFleetTrust(ctx, id(installation))
}
