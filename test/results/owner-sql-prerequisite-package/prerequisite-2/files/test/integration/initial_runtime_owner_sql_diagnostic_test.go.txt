package integration

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type ownerSQLPrerequisites struct {
	At                                                                   time.Time
	Administrative, Primary, Schema, Activation, Claim, Audit, Activated bool
	Trust, Unsuspended, Recovery, NotFuture, Unexpired, Interval         bool
	ObservedAt, FreshUntil                                               pgtype.Timestamptz
}

func (v ownerSQLPrerequisites) stable() bool {
	return v.Administrative && v.Primary && v.Schema && v.Activation && v.Claim && v.Audit && v.Activated && v.Trust && v.Recovery && v.NotFuture && v.Interval
}
func (v ownerSQLPrerequisites) current() bool { return v.stable() && v.Unsuspended && v.Unexpired }

type ownerSQLDiagnosticQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Fixed read-only diagnostic of the constructor's individual prerequisites.
// It is never consumed as authority. All timestamps belong to this exact
// sample; it cannot reconstruct predicates at a previous failed statement.
func readOwnerSQLPrerequisites(ctx context.Context, q ownerSQLDiagnosticQuery, input contracts.OwnerIdentityRoles) (ownerSQLPrerequisites, error) {
	var v ownerSQLPrerequisites
	bundle, err := postgres.EmbeddedInitialSchema()
	if err != nil {
		return v, err
	}
	err = q.QueryRow(ctx, `WITH moment AS MATERIALIZED (SELECT clock_timestamp() AS at)
 SELECT moment.at,
 COALESCE(p.rolsuper AND p.rolcanlogin AND current_user=session_user,false),NOT pg_is_in_recovery(),
 COALESCE((SELECT version_id=$3 AND is_applied FROM public.goose_db_version ORDER BY id DESC LIMIT 1),false),
 a.installation_id IS NOT NULL,COALESCE(a.claim_id=$2,false),a.audit_receipt_json IS NOT NULL,a.activated_at IS NOT NULL,
 t.installation_id IS NOT NULL,COALESCE(NOT t.suspended,false),COALESCE(NOT t.recovery_blocked,false),
 COALESCE(t.observed_at<=moment.at,false),COALESCE(moment.at<t.fresh_until,false),
 COALESCE(t.fresh_until-t.observed_at<=interval '30 seconds',false),t.observed_at,t.fresh_until
 FROM moment LEFT JOIN pg_roles p ON p.rolname=session_user
 LEFT JOIN public.fleet_initial_activation a ON a.installation_id=$1
 LEFT JOIN public.fleet_current_trust t ON t.installation_id=$1`, input.InstallationID, input.InitialClaimID, bundle.Head).Scan(
		&v.At, &v.Administrative, &v.Primary, &v.Schema, &v.Activation, &v.Claim, &v.Audit, &v.Activated, &v.Trust, &v.Unsuspended, &v.Recovery, &v.NotFuture, &v.Unexpired, &v.Interval, &v.ObservedAt, &v.FreshUntil)
	return v, err
}
