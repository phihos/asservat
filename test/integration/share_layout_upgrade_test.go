package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
)

// Uses the existing owned upgrade database, not a second service fixture.
// Temporary NOLOGIN roles qualify real view ownership and table/column grants.
func qualifyShareLayoutUpgrade(t *testing.T, ctx context.Context, conn *pgx.Conn, provider *goose.Provider) {
	t.Helper()
	checkRecipientIndex := func(partial bool) {
		t.Helper()
		var method, column string
		var predicate *string
		if err := conn.QueryRow(ctx, `SELECT a.amname,pg_get_indexdef(i.indexrelid,1,true),pg_get_expr(i.indpred,i.indrelid)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indexrelid='public.evidence_share_recipient'::regclass AND i.indrelid='public.evidence_share'::regclass`).Scan(&method, &column, &predicate); err != nil || method != "gin" || column != "recipient_keys" || partial && (predicate == nil || *predicate != "(revoked_at IS NULL)") || !partial && predicate != nil {
			t.Fatal("share recipient index shape after migration", method, column, predicate, partial, err)
		}
	}
	checkLayouts := func(current bool) {
		t.Helper()
		if current {
			qualifyShareBusinessWALMinimum(t, ctx, conn)
		}
		for _, row := range []struct {
			lane, layout string
			valid        bool
			transitions  int64
		}{
			{"normal", "operation-audit-history/v1", true, 16}, {"normal", "operation-audit-history/v2", true, 19},
			{"normal", "operation-audit-history/v3", true, 21}, {"resolution", "operation-audit-history/v3", true, 21},
			{"normal", "operation-audit-history/v4", current, 24}, {"resolution", "operation-audit-history/v4", current, 24},
			{"capture", "capture-intent-history/v1", true, 32}, {"capture", "capture-intent-history/v2", current, 34},
			{"identity", "operation-audit-history/v4", false, 24}, {"processing", "operation-audit-history/v4", false, 24},
		} {
			var valid bool
			var transitions *int64
			if err := conn.QueryRow(ctx, `SELECT public.operation_audit_history_layout_valid($1,$2),public.operation_audit_history_fixed_transitions($2)`, row.lane, row.layout).Scan(&valid, &transitions); err != nil || valid != row.valid {
				t.Fatal("actual SQL audit layout", row.lane, row.layout, valid, err)
			}
			fresh := row.layout == "operation-audit-history/v4" || row.layout == "capture-intent-history/v2"
			if !current && fresh {
				if transitions != nil {
					t.Fatal("Down retained new fixed transition layout", row.layout)
				}
			} else if transitions == nil || *transitions != row.transitions {
				t.Fatal("actual SQL fixed transition budget", row.layout, transitions)
			}
		}
		for _, pair := range []struct{ lane, old, next string }{
			{"normal", "operation-audit-history/v3", "operation-audit-history/v4"},
			{"capture", "capture-intent-history/v1", "capture-intent-history/v2"},
		} {
			var promoted bool
			if err := conn.QueryRow(ctx, `SELECT public.operation_audit_profile_covers(jsonb_build_object('Lane',$1::text,'History',jsonb_build_object('Layout',$2::text)),jsonb_build_object('Lane',$1::text,'History',jsonb_build_object('Layout',$3::text)))`, pair.lane, pair.next, pair.old).Scan(&promoted); err != nil || promoted {
				t.Fatal("retained profile implicitly promoted", pair.lane, err)
			}
		}
		var floor string
		want := "asservat:oldest-binary-schema=153"
		if current {
			want = "asservat:oldest-binary-schema=154"
		}
		if err := conn.QueryRow(ctx, `SELECT obj_description('public.goose_db_version'::regclass,'pg_class')`).Scan(&floor); err != nil || floor != want {
			t.Fatal("share layout compatibility floor", floor, want, err)
		}
	}
	views := []string{"capture_operation_lifecycle", "connector_operation_lifecycle"}
	owners := map[string]string{}
	for _, view := range views {
		var owner string
		if err := conn.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=$1::regclass`, "public."+view).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		owners[view] = owner
	}
	prefix := "share_acl_" + strings.ReplaceAll(custodyID(), "-", "")
	owner, reader, column := prefix+"_o", prefix+"_r", prefix+"_c"
	roles := []string{owner, reader, column}
	for _, role := range roles {
		if _, err := conn.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" NOLOGIN NOINHERIT"); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, view := range views {
			if _, err := conn.Exec(cleanup, "ALTER VIEW public."+pgx.Identifier{view}.Sanitize()+" OWNER TO "+pgx.Identifier{owners[view]}.Sanitize()); err != nil {
				t.Error("restore original lifecycle view owner", err)
				return
			}
		}
		for _, role := range roles {
			if _, err := conn.Exec(cleanup, "DROP OWNED BY "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("remove temporary view grants", err)
				continue
			}
			if _, err := conn.Exec(cleanup, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Error("remove temporary view role", err)
			}
		}
	}()
	if _, err := conn.Exec(ctx, "GRANT USAGE,CREATE ON SCHEMA public TO "+pgx.Identifier{owner}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		name := "public." + pgx.Identifier{view}.Sanitize()
		if _, err := conn.Exec(ctx, "ALTER VIEW "+name+" OWNER TO "+pgx.Identifier{owner}.Sanitize()+"; GRANT SELECT ON "+name+" TO "+pgx.Identifier{reader}.Sanitize()+" WITH GRANT OPTION; GRANT UPDATE (lease) ON "+name+" TO "+pgx.Identifier{column}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := conn.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object('name',c.relname,'owner',c.relowner,
   'table',COALESCE((SELECT jsonb_agg(jsonb_build_array(x.grantor,x.grantee,x.privilege_type,x.is_grantable) ORDER BY x.grantor,x.grantee,x.privilege_type) FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x),'[]'::jsonb),
   'columns',COALESCE((SELECT jsonb_agg(jsonb_build_array(a.attname,x.grantor,x.grantee,x.privilege_type,x.is_grantable) ORDER BY a.attname,x.grantor,x.grantee,x.privilege_type) FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),'[]'::jsonb)) ORDER BY c.relname)::text
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('capture_operation_lifecycle','connector_operation_lifecycle')`).Scan(&value); err != nil {
			t.Fatal("lifecycle owner/grant snapshot", err)
		}
		return value
	}
	columns := func(markers bool) {
		t.Helper()
		var count int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('capture_operation_lifecycle','connector_operation_lifecycle') AND column_name IN ('share_effect_target','share_effect_xid')`).Scan(&count); err != nil || count != map[bool]int{true: 4, false: 0}[markers] {
			t.Fatal("lifecycle view marker projection", count, err)
		}
	}
	checkLayouts(true)
	columns(true)
	checkRecipientIndex(true)
	before := snapshot()
	// An actual grant on a new-only column cannot be silently discarded by Down.
	if _, err := conn.Exec(ctx, "GRANT UPDATE (share_effect_target) ON public.capture_operation_lifecycle TO "+pgx.Identifier{column}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	unsupported := snapshot()
	_, err := provider.DownTo(ctx, 153)
	var refusal *pgconn.PgError
	if !errors.As(err, &refusal) || refusal.Code != "23514" || !strings.Contains(refusal.Message, "marker-column grants") {
		t.Fatal("new-only column grant did not refuse Down atomically", err)
	}
	if snapshot() != unsupported {
		t.Fatal("failed Down changed retained owner or grants")
	}
	checkLayouts(true)
	columns(true)
	if _, err := conn.Exec(ctx, "REVOKE UPDATE (share_effect_target) ON public.capture_operation_lifecycle FROM "+pgx.Identifier{column}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if snapshot() != before {
		t.Fatal("marker grant revocation changed original grants")
	}
	if _, err := provider.DownTo(ctx, 153); err != nil {
		t.Fatal("empty SQL154 Down", err)
	}
	checkLayouts(false)
	columns(false)
	checkRecipientIndex(true) // SQL154 does not own this SQL153 index.
	if snapshot() != before {
		t.Fatal("SQL154 Down changed lifecycle owners/table/column grants")
	}
	// SQL153 can now remove its marker columns without view dependency errors.
	if _, err := provider.DownTo(ctx, 152); err != nil {
		t.Fatal("standalone SQL153 Down after SQL154", err)
	}
	checkRecipientIndex(false)
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("SQL153/154 Up after empty roundtrip", err)
	}
	checkLayouts(true)
	columns(true)
	checkRecipientIndex(true)
	if snapshot() != before {
		t.Fatal("SQL153/154 roundtrip changed lifecycle owners/table/column grants")
	}
	t.Log("SQL154 admitted fixed24/34 layouts without old-profile promotion; empty Down154/153/Up preserved actual owners and table/column grant options; new-only grants refused atomically")
}

// Exercise the final SQL protected-source validator against Go-produced policies:
// protocol-only backing and one-byte-short backing must both refuse v4.
func qualifyShareBusinessWALMinimum(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	id := "40000000-0000-4000-8000-000000000001"
	for _, lane := range []string{"normal", "resolution"} {
		q := audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: audit.ShareOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3}
		b, w := q.SlotBacking(4)
		v := capacityapp.RootAuditBacking{Accounts: 2, RecordsPerAccount: 3, RetainedSeconds: 10000, Policy: audit.OperationLifecyclePolicy{RootID: id, Lane: lane, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 1, MetadataSlots: 6, BackupReservedBytes: 6 * b, WALReservedBytes: 6 * w, BackupHorizonSeconds: 1, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), MaxPurgeLeases: 4, History: &q, OverdueTerminal: audit.OperationOverdueTerminal}}
		for _, tc := range []struct {
			name    string
			missing int64
			valid   bool
		}{
			{"exact", 0, true}, {"one-byte", 1, false}, {"protocol-only", 6 * 2 * 3 * (8 << 20), false},
		} {
			candidate := v
			candidate.Policy.WALReservedBytes -= tc.missing
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var valid bool
			err = conn.QueryRow(ctx, `SELECT capacity_root_audit_valid($1::jsonb,$2::uuid,$2::uuid,$3,'operation-audit-history/v4')`, raw, id, lane).Scan(&valid)
			if err != nil || valid != tc.valid {
				t.Fatal("SQL business WAL minimum", lane, tc.name, valid, err)
			}
		}
	}
}
