package postgres

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// VerifySQLConnectionBudget reads the actual server settings under the same
// original activation/incarnation and five-second transaction as the bridge.
// It changes no settings, grants or pool limits and acquires no second pool.
// Zero allocation selects the server's whole ordinary connection capacity.
func (s *InitialRuntimeBridgeSQL) VerifySQLConnectionBudget(ctx context.Context, plan contracts.SQLConnectionPlan, allocation int) (contracts.SQLConnectionBudget, error) {
	var out contracts.SQLConnectionBudget
	err := s.withInitialRuntimeBridgeQuery(ctx, nil, func(call context.Context, q publicRoleQuery) error {
		var err error
		out, err = readSQLConnectionBudget(call, q, plan, allocation)
		return err
	})
	return out, err
}

func readSQLConnectionBudget(ctx context.Context, q publicRoleQuery, plan contracts.SQLConnectionPlan, allocation int) (contracts.SQLConnectionBudget, error) {
	var server contracts.SQLServerCapacity
	if ctx == nil || ctx.Err() != nil || q == nil {
		return contracts.SQLConnectionBudget{}, cfg.ErrUnavailable
	}
	err := q.QueryRow(ctx, `SELECT current_setting('max_connections')::int,
 current_setting('superuser_reserved_connections')::int,
 COALESCE(current_setting('reserved_connections',true),'0')::int`).Scan(&server.MaxConnections, &server.SuperuserReserved, &server.Reserved)
	if err != nil || ctx.Err() != nil {
		return contracts.SQLConnectionBudget{}, cfg.ErrUnavailable
	}
	return plan.Validate(allocation, server)
}
