package integration

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This later administrator snapshot does not reconstruct the failed invocation
// or confer authority. Only fixed booleans, intervals and a revision leave SQL;
// source configuration, provenance, credentials and request contents do not.
// The checks cover the current-state guard of read_capacity_audit_profiles,
// excluding its caller-specific qualification/account arguments and deadline.
const installedCapacityCurrentQuery = `WITH sampled AS MATERIALIZED (SELECT clock_timestamp() AS at)
SELECT sampled.at, ARRAY[
 t.installation_id IS NOT NULL, p.id IS NOT NULL, s.root_id IS NOT NULL,
 coalesce(public.capacity_audit_reader_pin_valid(s),false),
 EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=s.audit_reader_role AND rolname=$3),
 coalesce(s.installation_id=$2::uuid,false),
 coalesce(NOT t.suspended AND NOT t.recovery_blocked AND t.observed_at<=sampled.at AND t.fresh_until>sampled.at,false),
 coalesce(NOT p.suspended AND p.observed_at<=sampled.at AND p.fresh_until>sampled.at AND p.lease_until>sampled.at AND p.fresh_until<=p.observed_at+interval '5 seconds',false),
 coalesce(NOT s.suspended AND s.observed_at<=sampled.at AND s.fresh_until>sampled.at AND s.accepted_revision>=1 AND s.accepted_snapshot IS NOT NULL,false),
 coalesce(public.capacity_root_configuration_valid(s.root_configuration),false),
 CASE WHEN coalesce(public.capacity_root_configuration_valid(s.root_configuration),false)
 THEN coalesce(s.root_configuration->'ReadyAt'<>'null'::jsonb AND (s.root_configuration->>'ReadyAt')::timestamptz<=sampled.at,false) ELSE false END,
 coalesce(s.root_configuration->'ReconciledAt'='null'::jsonb,false),
 s.root_plan IS NOT NULL, s.root_mutation_xid IS NOT NULL,
 CASE WHEN coalesce(public.capacity_root_configuration_valid(s.root_configuration),false)
 THEN public.connector_digest(s.root_configuration->'PlanDigest') IS NOT DISTINCT FROM s.root_plan_digest AND s.root_plan_digest IS NOT NULL ELSE false END,
 coalesce(s.root_plan->'Input' IS NOT DISTINCT FROM s.qualification->'RootBacking' AND s.root_plan IS NOT NULL,false),
 EXISTS(SELECT 1 FROM public.authority_audit WHERE id=p.initial_audit_id AND stream_id=$1 AND acknowledged_at IS NOT NULL),
 EXISTS(SELECT 1 FROM public.authority_audit WHERE id=p.epoch AND stream_id=$1 AND acknowledged_at IS NOT NULL)
 ], ARRAY[
 (extract(epoch FROM (t.fresh_until-sampled.at))*1000)::bigint,
 (extract(epoch FROM (p.fresh_until-sampled.at))*1000)::bigint,
 (extract(epoch FROM (p.lease_until-sampled.at))*1000)::bigint,
 (extract(epoch FROM (s.fresh_until-sampled.at))*1000)::bigint,
 CASE WHEN coalesce(public.capacity_root_configuration_valid(s.root_configuration),false)
 THEN (extract(epoch FROM ((s.root_configuration->>'PlannedUntil')::timestamptz-sampled.at))*1000)::bigint ELSE NULL::bigint END
 ], coalesce(s.accepted_revision,0)
FROM sampled
LEFT JOIN public.fleet_current_trust t ON t.installation_id=$2::uuid
LEFT JOIN public.permission_stream p ON p.id=$1::uuid
LEFT JOIN public.capacity_source s ON s.root_id=$1::uuid
LIMIT 1`

func installedCapacityCurrentDiagnostics(ctx context.Context, query func(context.Context, string, ...any) pgx.Row, root, installation string, logf func(string, ...any)) {
	role, valid := postgres.PublicRuntimeRoleName(installation, "capacity-profile-read")
	if !valid || !authorization.UUID(root) {
		logf("diagnostics: capacity current unavailable (scope)")
		return
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if call.Err() != nil {
		logf("diagnostics: capacity current unavailable (caller)")
		return
	}
	var at time.Time
	var checks []bool
	var remaining []pgtype.Int8
	var revision int64
	err := query(call, installedCapacityCurrentQuery, root, installation, role).Scan(&at, &checks, &remaining, &revision)
	if err != nil || call.Err() != nil || at.IsZero() || len(checks) != 18 || len(remaining) != 5 || revision < 0 || revision >= 1<<60 {
		logf("diagnostics: capacity current unavailable (read)")
		return
	}
	// Labels are fixed here; no database text or provider error is printed.
	logf("diagnostics: capacity current snapshot_at=%s (later read, not failed invocation state) accepted_revision=%d", at.UTC().Format(time.RFC3339Nano), revision)
	logf("diagnostics: capacity current trust_present=%t permission_present=%t source_present=%t reader_pin_valid=%t reader_role_matches=%t installation_matches=%t trust_current=%t permission_current=%t source_current=%t root_configuration_valid=%t root_ready=%t root_unreconciled=%t root_plan_present=%t root_mutation_present=%t root_digest_matches=%t root_input_matches=%t initial_audit_acknowledged=%t epoch_audit_acknowledged=%t", checks[0], checks[1], checks[2], checks[3], checks[4], checks[5], checks[6], checks[7], checks[8], checks[9], checks[10], checks[11], checks[12], checks[13], checks[14], checks[15], checks[16], checks[17])
	for i, name := range []string{"trust", "permission", "permission_lease", "source", "root_planned"} {
		if remaining[i].Valid {
			logf("diagnostics: capacity current %s_remaining_ms=%d", name, remaining[i].Int64)
		} else {
			logf("diagnostics: capacity current %s_remaining_ms=unknown", name)
		}
	}
}
