package integration

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
)

const installedSQLActivityRows = 64

// This fixed projection deliberately excludes query text, parameters, client
// addresses and application names. The extra row reports truncation without
// expanding the diagnostic's output budget.
const installedSQLActivityQuery = `SELECT usename::text,
 left(coalesce(state, ''), 32),
 left(coalesce(wait_event_type, ''), 32),
 left(coalesce(wait_event, ''), 64),
 CASE WHEN xact_start IS NULL THEN -1 ELSE greatest(0, extract(epoch FROM (clock_timestamp() - xact_start)) * 1000)::bigint END,
 CASE WHEN query_start IS NULL THEN -1 ELSE greatest(0, extract(epoch FROM (clock_timestamp() - query_start)) * 1000)::bigint END
 FROM pg_catalog.pg_stat_activity
 WHERE datname = current_database() AND usename = ANY($1::text[])
 ORDER BY (state IS DISTINCT FROM 'idle') DESC, xact_start ASC NULLS LAST, usename, pid
 LIMIT 65`

// Run before the journey's Pod log collection and deferred owner removal, using
// the existing administrator connection only for this finite read. A diagnostic
// failure is logged with a fixed label and cannot replace the primary failure.
func installedSQLActivityDiagnostics(ctx context.Context, query func(context.Context, string, ...any) (pgx.Rows, error), installation string, logf func(string, ...any)) {
	roles := installedSQLActivityRoles(installation)
	if len(roles) == 0 {
		logf("diagnostics: SQL activity unavailable (installation)")
		return
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if call.Err() != nil {
		logf("diagnostics: SQL activity unavailable (caller)")
		return
	}
	rows, err := query(call, installedSQLActivityQuery, roles)
	if err != nil {
		logf("diagnostics: SQL activity unavailable (query)")
		return
	}
	defer rows.Close()
	count := 0
	for ; rows.Next(); count++ {
		if call.Err() != nil {
			logf("diagnostics: SQL activity unavailable (caller)")
			return
		}
		if count == installedSQLActivityRows {
			logf("diagnostics: SQL activity truncated at %d rows", installedSQLActivityRows)
			return
		}
		var role, state, waitType, event string
		var transactionMS, queryMS int64
		if rows.Scan(&role, &state, &waitType, &event, &transactionMS, &queryMS) != nil {
			logf("diagnostics: SQL activity unavailable (row)")
			return
		}
		// Keep output finite and installation-scoped even if a test substitute
		// returns rows that do not obey the fixed server-side projection.
		if !slices.Contains(roles, role) || len(state) > 32 || len(waitType) > 32 || len(event) > 64 {
			logf("diagnostics: SQL activity unavailable (row)")
			return
		}
		logf("diagnostics: SQL activity role=%q state=%q wait_type=%q event=%q transaction_ms=%d query_ms=%d",
			role, state, waitType, event, transactionMS, queryMS)
	}
	if rows.Err() != nil {
		logf("diagnostics: SQL activity unavailable (read)")
		return
	}
	logf("diagnostics: SQL activity rows=%d", count)
}

func installedSQLActivityRoles(installation string) []string {
	var roles []string
	for _, group := range []struct {
		purposes []string
		name     func(string, string) (string, bool)
	}{
		{contracts.PublicRuntimeRolePurposes(), postgres.PublicRuntimeRoleName},
		{contracts.ConfigurationRuntimeRolePurposes(), postgres.ConfigurationRuntimeRoleName},
		{contracts.OwnerIdentityRolePurposes(), postgres.OwnerIdentityRoleName},
	} {
		for _, purpose := range group.purposes {
			role, ok := group.name(installation, purpose)
			if !ok {
				return nil
			}
			roles = append(roles, role)
		}
	}
	return roles
}
