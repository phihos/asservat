package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Pristine143 Up/Down/Up against the integrated142 baseline; no installed role,
// source delivery or live traffic claim follows from a schema round trip.
func TestLiveWatchUpgradeWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("owned PostgreSQL fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "live_upgrade_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		call, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		if _, err := admin.Exec(call, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("owned database cleanup", err)
		}
	})
	endpoint, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, tlsConfig := pgTLSBridge(t, endpoint.Host)
	pc, err := pgxpool.ParseConfig("postgres://" + endpoint.User.String() + "@" + address + "/" + name + "?sslmode=disable")
	if err != nil {
		t.Fatal("fixture endpoint")
	}
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	db := stdlib.OpenDB(*pc.ConnConfig)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range provider.ListSources() {
		if s.Version == 142 {
			found = true
		}
	}
	if !found {
		t.Fatal("final142 is not integrated: provisional143 cannot be qualified")
	}
	if _, err = provider.UpTo(ctx, 142); err != nil {
		t.Fatal("original142", err)
	}
	const defs = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.operation_audit_lane(text)','public.operation_audit_human_input_valid(text,text)','public.project_context_processing()']) f`
	const shape = `SELECT jsonb_build_object('columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.table_name,c.ordinal_position) FROM information_schema.columns c WHERE c.table_schema='public'),'constraints',(SELECT jsonb_agg(jsonb_build_array(r.relname,c.conname,pg_get_constraintdef(c.oid)) ORDER BY r.relname,c.conname) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public'),'indexes',(SELECT jsonb_agg(jsonb_build_array(tablename,indexname,indexdef) ORDER BY tablename,indexname) FROM pg_indexes WHERE schemaname='public'))::text`
	var beforeDefs, beforeShape string
	if err = pool.QueryRow(ctx, defs).Scan(&beforeDefs); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, shape).Scan(&beforeShape); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		if _, err = provider.UpTo(ctx, 143); err != nil {
			t.Fatal("143 Up", round, err)
		}
		var count int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relname IN ('live_watch_root','live_watch_account','live_watch_control')`).Scan(&count); err != nil || count != 3 {
			t.Fatal("bounded ledger tables", count, err)
		}
		if _, err = provider.DownTo(ctx, 142); err != nil {
			t.Fatal("143 Down", round, err)
		}
		var afterDefs, afterShape string
		if err = pool.QueryRow(ctx, defs).Scan(&afterDefs); err != nil || afterDefs != beforeDefs {
			t.Fatal("Down changed exact142 audit definitions", err)
		}
		if err = pool.QueryRow(ctx, shape).Scan(&afterShape); err != nil || afterShape != beforeShape {
			t.Fatal("Down changed142 full schema shape", err)
		}
		var helpers int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'live_watch_%'`).Scan(&helpers); err != nil || helpers != 0 {
			t.Fatal("new helper retained at142", helpers, err)
		}
	}
	if _, err = provider.UpTo(ctx, 143); err != nil {
		t.Fatal("final143 Up", err)
	}
	// Exercise the actual fixed SQL Open/Charge functions under the compiled
	// hub duty. Trust, permission root and owner identity are synthetic here;
	// this is retained-ledger rollback proof, not owner/C3 admission proof.
	installation, issuer, root, owner := custodyID(), custodyID(), custodyID(), custodyID()
	if _, err = pool.Exec(ctx, `INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-live-rollback',1,$3,false,false,clock_timestamp(),clock_timestamp()+interval '30 seconds')`, installation, issuer, bytes.Repeat([]byte{42}, 32)); err != nil {
		t.Fatal("synthetic rollback trust", err)
	}
	if _, err = seedSyntheticFleetObservation(ctx, pool, installation); err != nil {
		t.Fatal("synthetic rollback fleet observation", err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO permission_stream(id,epoch,trust_digest,lease_until) VALUES($1,$2,$3,clock_timestamp()+interval '30 seconds')`, root, custodyID(), bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal("synthetic rollback root", err)
	}
	role := narrowRole(t, ctx, pool, "live_rollback_", "synthetic-live-rollback", func(name string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", name)
		if !ok {
			t.Fatal("compiled rollback role")
		}
		return grants
	})
	runtimeConfig := pc.Copy()
	runtimeConfig.ConnConfig.User = role
	runtimeConfig.ConnConfig.Password = "synthetic-live-rollback"
	runtimeConfig.MaxConns = 1
	runtimePool, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatal("compiled rollback pool", err)
	}
	t.Cleanup(runtimePool.Close)
	limits := postgres.LiveWatchLimits{InstallationSlots: 1, PrincipalSlots: 1, WorkloadSlots: 1, MemoryBytes: 1 << 20, InstallationRate: 1, InstallationBurst: 24 << 10, PrincipalRate: 1, PrincipalBurst: 24 << 10, WorkloadRate: 1, WorkloadBurst: 24 << 10, WatchBurst: 24 << 10, MaxOutputBytes: 24 << 10, MaxRate: 1, MaxDurationSeconds: 2, MaxAccounts: 3, MaxControlRecords: 1}
	encodedLimits, err := json.Marshal(limits)
	if err != nil || !limits.Valid() {
		t.Fatal("rollback limits", err)
	}
	digest := sha256.Sum256(encodedLimits)
	var configured bool
	if err = runtimePool.QueryRow(ctx, `SELECT live_watch_configure($1,$2,$3,$4,$5)`, root, installation, issuer, digest[:], encodedLimits).Scan(&configured); err != nil || !configured {
		t.Fatal("compiled configure", configured, err)
	}
	var accepted time.Time
	if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&accepted); err != nil {
		t.Fatal(err)
	}
	accepted = accepted.UTC().Truncate(time.Microsecond)
	control := liveapp.Control{ID: custodyID(), OwnerID: owner, Fence: custodyID(), PrincipalKey: [32]byte{1}, WorkloadKey: [32]byte{2}, RequestDigest: [32]byte{3}, Revision: 1, State: "Active", AcceptedAt: accepted, ExpiresAt: accepted.Add(2 * time.Second), IdleUntil: accepted.Add(2 * time.Second), OutputLimit: 24 << 10, BytesPerSecond: 1}
	encodedControl, err := json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	var opened struct {
		Control liveapp.Control `json:"control"`
		Reused  bool            `json:"reused"`
	}
	var result []byte
	if err = runtimePool.QueryRow(ctx, `SELECT live_watch_create($1,$2,$3,$4,$5,$6)`, root, owner, digest[:], encodedControl, bytes.Repeat([]byte{4}, 32), control.ExpiresAt).Scan(&result); err != nil || json.Unmarshal(result, &opened) != nil || opened.Reused || opened.Control != control {
		t.Fatal("compiled original Open", err)
	}
	control.Spent = 4 << 10
	encodedControl, err = json.Marshal(control)
	if err != nil {
		t.Fatal(err)
	}
	var charged liveapp.Control
	if err = runtimePool.QueryRow(ctx, `SELECT live_watch_change($1,$2,$3,$4,1,4096,$5)`, root, owner, digest[:], encodedControl, control.ExpiresAt).Scan(&result); err != nil || json.Unmarshal(result, &charged) != nil || charged != control {
		t.Fatal("compiled original Charge", err)
	}
	// A failed migration must not change even one retained receipt, stored debt,
	// schema/function definition or Goose version/history row.
	const retained = `SELECT jsonb_build_object('root',(SELECT jsonb_agg(to_jsonb(r) ORDER BY root_id) FROM live_watch_root r),'controls',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM live_watch_control w),'accounts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY root_id,kind,account_key) FROM live_watch_account a),'history',(SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM goose_db_version h),'functions',(SELECT jsonb_agg(pg_get_functiondef(p.oid) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind<>'a'))::text`
	assertRetainedDown := func(stage string) {
		t.Helper()
		var originalState, originalShape, currentState, currentShape string
		if err := pool.QueryRow(ctx, retained).Scan(&originalState); err != nil {
			t.Fatal(stage, "original retained state", err)
		}
		if err := pool.QueryRow(ctx, shape).Scan(&originalShape); err != nil {
			t.Fatal(stage, "original retained schema", err)
		}
		_, downErr := provider.DownTo(ctx, 142)
		var pgError *pgconn.PgError
		if !errors.As(downErr, &pgError) || pgError.Code != "23514" {
			t.Fatal(stage, "retained Down did not refuse", downErr)
		}
		if err := pool.QueryRow(ctx, retained).Scan(&currentState); err != nil || currentState != originalState {
			t.Fatal(stage, "Down changed retained state/functions/history", err)
		}
		if err := pool.QueryRow(ctx, shape).Scan(&currentShape); err != nil || currentShape != originalShape {
			t.Fatal(stage, "Down changed retained schema", err)
		}
	}
	var controls, accounts int
	var debt bool
	const counts = `SELECT (SELECT count(*) FROM live_watch_control),(SELECT count(*) FROM live_watch_account),(SELECT bool_and(tokens_micro<24576::bigint*1000000) FROM live_watch_account)`
	if err = pool.QueryRow(ctx, counts).Scan(&controls, &accounts, &debt); err != nil || controls != 1 || accounts != 3 || !debt {
		t.Fatal("original charged control/accounts", controls, accounts, debt, err)
	}
	assertRetainedDown("control+debt")
	// Wait only for the original two-second end; no timestamp rewrite, receipt
	// deletion or refund. At 1 B/s the original 4 KiB charge cannot yet refill.
	wait := time.NewTimer(time.Until(control.ExpiresAt))
	defer wait.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("original rollback expiry", ctx.Err())
	case <-wait.C:
	}
	var pruned struct {
		Controls int `json:"controls"`
		Accounts int `json:"accounts"`
	}
	if err = runtimePool.QueryRow(ctx, `SELECT live_watch_prune($1)`, root).Scan(&result); err != nil || json.Unmarshal(result, &pruned) != nil || pruned.Controls != 1 || pruned.Accounts != 0 {
		t.Fatal("bounded original-expiry prune", pruned, err)
	}
	if err = pool.QueryRow(ctx, counts).Scan(&controls, &accounts, &debt); err != nil || controls != 0 || accounts != 3 || !debt {
		t.Fatal("account-only original debt", controls, accounts, debt, err)
	}
	assertRetainedDown("debt-only")
	t.Log("pristine142→143→142 twice; final143 compiled Open/Charge; retained control and account-only debt each refuse Down23514 with exact schema/functions/history/state unchanged; HTTP/source/audit retained guards not exercised")
}
