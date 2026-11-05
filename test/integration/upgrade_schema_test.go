package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// ADR-227 phase 1: an installed database one migration behind is upgraded by
// the schema owner; the upgrade is idempotent, records the compatibility floor
// and refuses a history it does not know.
func TestCustodyUpgradeSchemaWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	ctx, end := context.WithTimeout(context.Background(), 4*time.Minute)
	defer end()
	admin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Close)
	name := "upgrade_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(bounded, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned database cleanup failed", e)
		}
	})
	endpoint, e := url.Parse(f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	address, roots := pgTLSBridge(t, endpoint.Host)
	host, portText, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(portText)
	config := admin.Config().ConnConfig.Copy()
	config.Host, config.Port, config.Database = host, uint16(port), name
	config.TLSConfig = roots.Clone()
	config.TLSConfig.MinVersion = tls.VersionTLS13
	config.Fallbacks = nil

	// An installation at the previous head, with an activated trust root.
	db := stdlib.OpenDB(*config)
	defer db.Close()
	p, e := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if e != nil {
		t.Fatal(e)
	}
	sources := p.ListSources()
	head := sources[len(sources)-1].Version
	if _, e = p.UpTo(ctx, head-1); e != nil {
		t.Fatal("migrate to previous head", e)
	}
	conn, e := pgx.ConnectConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, e = conn.Exec(ctx, `INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until,activated_postmaster_at,activated_database_oid)
 VALUES($1,$2,'synthetic-upgrade',1,$3,$4,$5,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()))`, custodyID(), custodyID(), make([]byte, 32), now, now.Add(time.Second)); e != nil {
		t.Fatal("synthetic activated installation", e)
	}

	// Retain the actual previous function and fixture trust row for the
	// function-only projection migration's Down/Up qualification.
	const refreshDefinition = `SELECT pg_get_functiondef('public.refresh_capacity_enrollment(uuid,jsonb,bytea,bytea,bytea,jsonb)'::regprocedure)`
	var originalFunction, originalTrust string
	if e = conn.QueryRow(ctx, refreshDefinition).Scan(&originalFunction); e != nil {
		t.Fatal("original refresh function", e)
	}
	if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&originalTrust); e != nil {
		t.Fatal("original fixture trust state", e)
	}

	const sourceDefinitions = `SELECT pg_get_functiondef('public.capacity_source_observation_valid(jsonb)'::regprocedure),pg_get_functiondef('public.capacity_source_monotonic(jsonb,jsonb)'::regprocedure)`
	var originalSourceValidator, originalMonotonic string
	if e = conn.QueryRow(ctx, sourceDefinitions).Scan(&originalSourceValidator, &originalMonotonic); e != nil {
		t.Fatal("previous source definitions", e)
	}
	// Migration 122 (ADR-282 slice 5) replaces these functions only.
	const queryDefinitions = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.operation_audit_human_input_valid(text,text)','public.guard_operation_audit()','public.context_query_intent_current(uuid,uuid,jsonb,uuid,jsonb)','public.context_query_outcome_closed(uuid,uuid,jsonb,uuid)','public.guard_context_query_account()','public.guard_context_query()','public.guard_context_query_child()']) f`
	var originalQueryFunctions string
	if e = conn.QueryRow(ctx, queryDefinitions).Scan(&originalQueryFunctions); e != nil {
		t.Fatal("previous query functions", e)
	}
	const syscallQueryDefinitions = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.context_query_scope_source_valid(jsonb)','public.context_query_begin_tool(jsonb)','public.context_query_read_batches(jsonb)','public.context_query_units(jsonb)','public.operation_audit_lane(text)','public.operation_audit_human_input_valid(text,text)','public.guard_operation_audit()','public.context_query_intent_current(uuid,uuid,jsonb,uuid,jsonb)','public.context_query_outcome_closed(uuid,uuid,jsonb,uuid)','public.guard_context_query()']) f`
	var originalSyscallQueryFunctions, originalKeyBindingConstraint string
	if head == 132 {
		if e = conn.QueryRow(ctx, syscallQueryDefinitions).Scan(&originalSyscallQueryFunctions); e != nil {
			t.Fatal("previous saved-query functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='public.context_query_key_binding'::regclass AND conname='context_query_key_binding_binding_check'`).Scan(&originalKeyBindingConstraint); e != nil {
			t.Fatal("previous key-child bound", e)
		}
	}
	const packetQueryDefinitions = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.context_query_scope_source_valid(jsonb)','public.context_query_begin_tool(jsonb)','public.context_query_read_batches(jsonb)','public.context_query_units(jsonb)','public.guard_context_query()','public.guard_context_query_child()','public.operation_audit_lane(text)','public.operation_audit_human_input_valid(text,text)','public.guard_operation_audit()','public.context_query_intent_current(uuid,uuid,jsonb,uuid,jsonb)']) f`
	const packetQueryShape = `SELECT jsonb_build_object('columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.ordinal_position) FROM (SELECT column_name,ordinal_position,is_nullable,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='context_query') c),'constraints',(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE conrelid IN ('context_query'::regclass,'access_grant'::regclass,'access_grant_use'::regclass)),'indexes',(SELECT jsonb_agg(indexdef ORDER BY indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename='context_query'))::text`
	var originalPacketQueryFunctions, originalPacketQueryShape string
	if head == 139 {
		if e = conn.QueryRow(ctx, packetQueryDefinitions).Scan(&originalPacketQueryFunctions); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, packetQueryShape).Scan(&originalPacketQueryShape); e != nil {
			t.Fatal(e)
		}
		var accepted bool
		if e = conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, packetQuerySQLScope(t, true)).Scan(&accepted); e != nil || accepted {
			t.Fatal("previous138 accepted raw pcap_query", e)
		}
	}
	const rawPacketDefinitions = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.context_query_scope_source_valid(jsonb)','public.context_query_begin_tool(jsonb)','public.context_query_read_batches(jsonb)','public.context_query_units(jsonb)','public.guard_context_query()']) f`
	var originalRawPacketFunctions string
	if head >= 138 && head <= 139 {
		if head > 138 {
			if _, e = p.DownTo(ctx, 137); e != nil {
				t.Fatal(e)
			}
		}
		if e = conn.QueryRow(ctx, rawPacketDefinitions).Scan(&originalRawPacketFunctions); e != nil {
			t.Fatal("original137 raw summary functions", e)
		}
	}
	var originalPacketFunctions string
	if head >= 137 && head <= 139 {
		if head > 137 {
			if _, e = p.DownTo(ctx, 136); e != nil {
				t.Fatal("capture pre137 functions", e)
			}
		}
		if e = conn.QueryRow(ctx, syscallQueryDefinitions).Scan(&originalPacketFunctions); e != nil {
			t.Fatal("original136 packet-query function boundary", e)
		}
	}

	const comparisonDefinitions = `SELECT string_agg(pg_get_functiondef(f::regprocedure),E'\n' ORDER BY f) FROM unnest(ARRAY['public.context_query_scope_source_valid(jsonb)','public.context_query_begin_tool(jsonb)','public.context_query_units(jsonb)','public.operation_audit_lane(text)','public.operation_audit_human_input_valid(text,text)','public.guard_operation_audit()','public.context_query_intent_current(uuid,uuid,jsonb,uuid,jsonb)','public.context_query_outcome_closed(uuid,uuid,jsonb,uuid)','public.guard_context_query()','public.guard_context_query_child()','public.guard_context_query_account()','public.guard_download_worker()']) f`
	const comparisonShape = `SELECT jsonb_build_object('columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.table_name,c.ordinal_position) FROM (SELECT table_name,column_name,ordinal_position,is_nullable,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('context_query','context_query_batch','context_query_key_binding','download_worker')) c),'constraints',(SELECT jsonb_agg(x ORDER BY x) FROM (SELECT conrelid::regclass::text||':'||pg_get_constraintdef(oid) x FROM pg_constraint WHERE conrelid IN ('context_query'::regclass,'context_query_batch'::regclass,'context_query_key_binding'::regclass,'download_worker'::regclass)) c),'indexes',(SELECT jsonb_agg(indexdef ORDER BY indexdef) FROM pg_indexes WHERE schemaname='public' AND tablename IN ('context_query','context_query_batch','context_query_key_binding','download_worker')))::text`
	var originalComparisonFunctions, originalComparisonShape string
	if head == 133 {
		if e = conn.QueryRow(ctx, comparisonDefinitions).Scan(&originalComparisonFunctions); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, comparisonShape).Scan(&originalComparisonShape); e != nil {
			t.Fatal(e)
		}
	}
	var originalAcquisitionGuard, originalAcquisitionShape string
	const acquisitionShape = `SELECT jsonb_build_object('columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.ordinal_position) FROM (SELECT column_name,ordinal_position,is_nullable,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name='context_verification') c),'constraints',(SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE conrelid='context_verification'::regclass))::text`
	if head >= 134 && head <= 139 {
		if head >= 135 {
			if _, e = p.DownTo(ctx, 133); e != nil {
				t.Fatal("capture pre134 verification guard", e)
			}
		}
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_context_verification()'::regprocedure)`).Scan(&originalAcquisitionGuard); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, acquisitionShape).Scan(&originalAcquisitionShape); e != nil {
			t.Fatal(e)
		}
		// Capture the actual pre-133 definitions, then restore the original
		// previous-head setup before exercising the production upgrader.
		if _, e = p.DownTo(ctx, 132); e != nil {
			t.Fatal("capture previous comparison shape", e)
		}
		if e = conn.QueryRow(ctx, comparisonDefinitions).Scan(&originalComparisonFunctions); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, comparisonShape).Scan(&originalComparisonShape); e != nil {
			t.Fatal(e)
		}
		if _, e = p.UpTo(ctx, head-1); e != nil {
			t.Fatal("restore previous schema before upgrade", e)
		}
	}
	// At 136 capture the actual pre-135 refusal definitions, then restore
	// the previous head before testing the production upgrader.
	if head >= 136 && head <= 139 {
		if _, e = p.DownTo(ctx, 134); e != nil {
			t.Fatal("capture pre135 execution guard", e)
		}
	}
	const profileDefinitions = `SELECT pg_get_functiondef('public.guard_custody_stream()'::regprocedure),pg_get_functiondef('public.project_context_processing()'::regprocedure),pg_get_functiondef('public.guard_context_execution()'::regprocedure)`
	var originalStreamGuard, originalProcessingProjector, originalExecutionGuard string
	if e = conn.QueryRow(ctx, profileDefinitions).Scan(&originalStreamGuard, &originalProcessingProjector, &originalExecutionGuard); e != nil {
		t.Fatal("previous profile functions", e)
	}
	const refusalExecutionShape = `SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname)::text FROM pg_constraint WHERE conrelid='context_execution'::regclass`
	var originalRefusalExecutionShape string
	if head >= 135 && head <= 139 {
		if e = conn.QueryRow(ctx, refusalExecutionShape).Scan(&originalRefusalExecutionShape); e != nil {
			t.Fatal(e)
		}
	}
	if head >= 136 && head <= 139 {
		if _, e = p.UpTo(ctx, 135); e != nil {
			t.Fatal("restore pre136 schema", e)
		}
	}
	const historyAdmissionShape = `SELECT jsonb_build_object('function',pg_get_functiondef('public.require_capacity_new_admission()'::regprocedure),'triggers',(SELECT jsonb_agg(jsonb_build_array(tgrelid::regclass::text,pg_get_triggerdef(oid)) ORDER BY tgrelid::regclass::text) FROM pg_trigger WHERE tgname='zzz_capacity_new_admission'))::text`
	var originalHistoryAdmission string
	if head >= 136 && head <= 139 {
		if e = conn.QueryRow(ctx, historyAdmissionShape).Scan(&originalHistoryAdmission); e != nil {
			t.Fatal(e)
		}
	}
	if head >= 137 && head <= 139 {
		if _, e = p.UpTo(ctx, head-1); e != nil {
			t.Fatal("restore previous schema before production upgrade", e)
		}
	}
	const profileCancelDefinition = `SELECT pg_get_functiondef('public.guard_snapshot_cancel()'::regprocedure)`
	var originalCancellation string
	if e = conn.QueryRow(ctx, profileCancelDefinition).Scan(&originalCancellation); e != nil {
		t.Fatal(e)
	}
	var originalCapacityBacking string
	if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.capacity_context_protocol_backing(jsonb,jsonb)'::regprocedure)`).Scan(&originalCapacityBacking); e != nil {
		t.Fatal(e)
	}
	// SQL128 extends existing counters/session fields; empty downgrade must
	// restore exact old functions, constraints and column shapes, not merely
	// decrement goose's recorded version.
	const argumentAuthorityShape = `SELECT jsonb_build_object(
 'functions',(SELECT jsonb_object_agg(f,pg_get_functiondef(f::regprocedure)) FROM unnest(ARRAY['public.spend_adhoc_observed_bytes(uuid,uuid,bigint)','public.protect_adhoc_observation_spend()','public.protect_policy_collection_spend()','public.protect_access_grant()']) f),
 'constraints',(SELECT jsonb_object_agg(conname,pg_get_constraintdef(oid)) FROM pg_constraint WHERE conrelid='public.policy_observation_session'::regclass),
 'columns',(SELECT jsonb_agg(jsonb_build_array(table_name,column_name,data_type,is_nullable,column_default) ORDER BY table_name,ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('policy_observation_session','policy_acceptance','access_grant','adhoc_observation_spend'))
 )::text`
	var originalArgumentAuthority string
	if head == 128 {
		if e = conn.QueryRow(ctx, argumentAuthorityShape).Scan(&originalArgumentAuthority); e != nil {
			t.Fatal("original argument authority shape", e)
		}
	}
	var originalRawGrantShape, originalRawGrantGuard, originalRawAuditFunctions string
	const rawAuditFunctions = `SELECT pg_get_functiondef('public.operation_audit_lane(text)'::regprocedure)||pg_get_functiondef('public.operation_audit_human_input_valid(text,text)'::regprocedure)`
	const rawGrantShape = `SELECT jsonb_build_object('constraints',(SELECT jsonb_agg(x ORDER BY x) FROM (SELECT pg_get_constraintdef(oid) x FROM pg_constraint WHERE conrelid IN ('access_grant'::regclass,'access_grant_child'::regclass)) q),'columns',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.table_name,c.ordinal_position) FROM (SELECT table_name,column_name,ordinal_position,is_nullable,data_type FROM information_schema.columns WHERE table_schema='public' AND table_name IN ('access_grant','access_grant_child')) c))::text`
	if head == 131 {
		if e = conn.QueryRow(ctx, rawAuditFunctions).Scan(&originalRawAuditFunctions); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, rawGrantShape).Scan(&originalRawGrantShape); e != nil {
			t.Fatal(e)
		}
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_access_grant()'::regprocedure)`).Scan(&originalRawGrantGuard); e != nil {
			t.Fatal(e)
		}
	}
	var originalNativeLengthGuard string
	if head == 130 {
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_context_verification()'::regprocedure)`).Scan(&originalNativeLengthGuard); e != nil {
			t.Fatal(e)
		}
	}
	upgrade, e := postgres.NewUpgradeSchema(config)
	if e != nil {
		t.Fatal(e)
	}
	defer upgrade.Close()
	// ADR-227 phase 2: the state before (the latest floor an applied migration
	// declared, or the head when none did) and the floor the pending
	// migration declares.
	floorMark := regexp.MustCompile(`asservat:oldest-binary-schema=([0-9]+)`)
	priorFloor := head - 1
	for _, source := range sources[:len(sources)-1] {
		b, e := fs.ReadFile(migrations.Files(), filepath.Base(source.Path))
		if e != nil {
			t.Fatal(e)
		}
		if m := floorMark.FindSubmatch(b); m != nil {
			if priorFloor, e = strconv.ParseInt(string(m[1]), 10, 64); e != nil {
				t.Fatal(e)
			}
		}
	}
	state, e := upgrade.State(ctx)
	if e != nil || state.Head != head-1 || state.Floor != priorFloor || state.Compatible(head) {
		t.Fatal("state before the upgrade", state, e)
	}
	// An expand migration leaves the floor; a contract migration declares its
	// own version as the new floor (ADR-227). Compare with the head
	// migration's own declaration, not with head.
	declared := state.Floor
	headSource, e := fs.ReadFile(migrations.Files(), filepath.Base(sources[len(sources)-1].Path))
	if e != nil {
		t.Fatal(e)
	}
	if m := floorMark.FindSubmatch(headSource); m != nil {
		if declared, e = strconv.ParseInt(string(m[1]), 10, 64); e != nil {
			t.Fatal(e)
		}
	}
	planned, e := upgrade.PlannedFloor(state)
	if e != nil || planned != declared {
		t.Fatal("planned floor", planned, declared, e)
	}
	from, to, e := upgrade.Run(ctx)
	if e != nil || from != head-1 || to != head {
		t.Fatal("upgrade", from, to, e)
	}
	if state, e = upgrade.State(ctx); e != nil || state.Head != head || state.Floor != planned || !state.Compatible(postgres.CompiledSchemaVersion) || state.Compatible(head-1) != (planned <= head-1) {
		t.Fatal("state after the upgrade", state, e)
	}
	var floor string
	if e = conn.QueryRow(ctx, "SELECT obj_description('public.goose_db_version'::regclass,'pg_class')").Scan(&floor); e != nil || !strings.HasPrefix(floor, "asservat:oldest-binary-schema=") {
		t.Fatal("compatibility floor not recorded", floor, e)
	}
	if from, to, e = upgrade.Run(ctx); e != nil || from != head || to != head {
		t.Fatal("repeated upgrade was not a no-op", from, to, e)
	}
	// Migration 103 changes this function only. Down restores its exact old
	// definition; it neither rewrites projections nor changes activation state.
	if head == 103 {
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("projection migration Down", e)
		}
		var restoredFunction, restoredTrust string
		if e = conn.QueryRow(ctx, refreshDefinition).Scan(&restoredFunction); e != nil || restoredFunction != originalFunction {
			t.Fatal("Down did not restore exact prior refresh function", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&restoredTrust); e != nil || restoredTrust != originalTrust {
			t.Fatal("Down changed fixture activation/recovery state", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("projection migration Up after Down", from, to, e)
		}
		t.Log("projection migration Down restored exact function; Up restored head; fixture activation/recovery unchanged")
	}
	if head == 104 {
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("resource projection Down", e)
		}
		var restoredValidator, restoredMonotonic, restoredTrust string
		if e = conn.QueryRow(ctx, sourceDefinitions).Scan(&restoredValidator, &restoredMonotonic); e != nil || restoredValidator != originalSourceValidator || restoredMonotonic != originalMonotonic {
			t.Fatal("Down changed prior source functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&restoredTrust); e != nil || restoredTrust != originalTrust {
			t.Fatal("Down changed trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("resource projection Up after Down", from, to, e)
		}
		t.Log("resource projection Down restored exact validators and unchanged trust; Up restored104; no old-decoder rollback qualification")
	}
	if head == 139 {
		qualifyPacketQuerySQLFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, 138); e != nil {
			t.Fatal("empty packet query Down", e)
		}
		var functions, shape, trust string
		if e = conn.QueryRow(ctx, packetQueryDefinitions).Scan(&functions); e != nil || functions != originalPacketQueryFunctions {
			t.Fatal("139 Down changed138 function definitions", e)
		}
		if e = conn.QueryRow(ctx, packetQueryShape).Scan(&shape); e != nil || shape != originalPacketQueryShape {
			t.Fatal("139 Down changed138 columns/constraints/indexes", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("139 Down changed trust", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 138 || to != 139 {
			t.Fatal("139 Up after Down", from, to, e)
		}
		qualifyPacketQuerySQLFunctions(t, ctx, conn)
		t.Log("pcap_query139→138→139 restores exact previous functions/schema/grant constraints/trust; new query4units2batches, oldsummary2units1batch")
	}
	if head >= 138 && head <= 139 {
		qualifyPacketSummaryQueryFunctions(t, ctx, conn, true)
		if _, e = p.DownTo(ctx, 137); e != nil {
			t.Fatal("empty raw summary Down", e)
		}
		var restored, trust string
		var accepted bool
		if e = conn.QueryRow(ctx, rawPacketDefinitions).Scan(&restored); e != nil || restored != originalRawPacketFunctions {
			t.Fatal("raw summary Down changed exact137 functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("raw Down changed trust/recovery", e)
		}
		if e = conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, packetSummarySQLScope(t, true)).Scan(&accepted); e != nil || accepted {
			t.Fatal("137 accepted raw source", e)
		}
		qualifyPacketSummaryQueryFunctions(t, ctx, conn)
		if from, to, e = upgrade.Run(ctx); e != nil || from != 137 || to != head {
			t.Fatal("raw Up after Down", from, to, e)
		}
		qualifyPacketSummaryQueryFunctions(t, ctx, conn, true)
		t.Log("raw138→137→138: exact five137 functions/trust restored; metadata stays supported, raw refused at137; two units/one batch; no new state/privileges")
	}
	if head >= 137 && head <= 139 {
		qualifyPacketSummaryQueryFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, 136); e != nil {
			t.Fatal("empty packet summary Down", e)
		}
		var restored, trust string
		if e = conn.QueryRow(ctx, syscallQueryDefinitions).Scan(&restored); e != nil || restored != originalPacketFunctions {
			t.Fatal("packet Down changed exact136 query/audit functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("packet Down changed trust/recovery", e)
		}
		var accepted bool
		if e = conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, packetSummarySQLScope(t)).Scan(&accepted); e != nil || accepted {
			t.Fatal("136 accepted packet source", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 136 || to != head {
			t.Fatal("packet Up after Down", from, to, e)
		}
		qualifyPacketSummaryQueryFunctions(t, ctx, conn)
		t.Logf("packet%d→136→%d: exact ten136 function definitions/trust restored, closed source, two units, one batch; no new state/privileges", head, head)
	}
	if head >= 133 && head <= 139 {
		qualifyProfileComparisonQueryFunctions(t, ctx, conn)
		qualifySavedSyscallQueryFunctions(t, ctx, conn)
		qualifyProfileSummaryQueryFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, 132); e != nil {
			t.Fatal("empty comparison Down", e)
		}
		var functions, shape, trust string
		if e = conn.QueryRow(ctx, comparisonDefinitions).Scan(&functions); e != nil || functions != originalComparisonFunctions {
			t.Fatal("comparison Down changed132 function definitions", e)
		}
		if e = conn.QueryRow(ctx, comparisonShape).Scan(&shape); e != nil || shape != originalComparisonShape {
			t.Fatal("comparison Down changed132 columns/constraints/indexes", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("comparison Down changed trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 132 || to != head {
			t.Fatal("comparison Up after Down", from, to, e)
		}
		qualifyProfileComparisonQueryFunctions(t, ctx, conn)
		t.Logf("comparison%d→132→%d: exact twelve existing function definitions, table/index/constraint shape and trust restored; closed pair/20 units/one batch", head, head)
	}
	if head >= 134 && head <= 139 {
		qualifyProfileComparisonQueryFunctions(t, ctx, conn)
		qualifySavedSyscallQueryFunctions(t, ctx, conn)
		qualifyProfileSummaryQueryFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, 133); e != nil {
			t.Fatal("empty acquisition metadata Down", e)
		}
		var guard, shape, trust string
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_context_verification()'::regprocedure)`).Scan(&guard); e != nil || guard != originalAcquisitionGuard {
			t.Fatal("acquisition Down changed original native-length guard", e)
		}
		if e = conn.QueryRow(ctx, acquisitionShape).Scan(&shape); e != nil || shape != originalAcquisitionShape {
			t.Fatal("acquisition Down changed previous column/constraint shape", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("acquisition Down changed trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 133 || to != head {
			t.Fatal("acquisition Up after Down", from, to, e)
		}
		t.Logf("acquisition%d→133→%d: paired nullable timing, exact native-length guard/shape restored and trust unchanged; prior query parity retained", head, head)
	}
	if head >= 135 && head <= 139 {
		if _, e = p.DownTo(ctx, 134); e != nil {
			t.Fatal("empty profile refusal Down", e)
		}
		var guard, shape, trust string
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.guard_context_execution()'::regprocedure)`).Scan(&guard); e != nil || guard != originalExecutionGuard {
			t.Fatal("profile refusal Down changed existing immutable execution guard", e)
		}
		if e = conn.QueryRow(ctx, refusalExecutionShape).Scan(&shape); e != nil || shape != originalRefusalExecutionShape {
			t.Fatal("profile refusal Down changed existing phase/empty-result constraints", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("profile refusal Down changed trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 134 || to != head {
			t.Fatal("profile refusal Up after Down", from, to, e)
		}
		t.Logf("profile refusal%d→134→%d: exact existing execution guard/constraints restored and trust unchanged", head, head)
	}
	if head >= 136 && head <= 139 {
		var deferrable, deferred bool
		if e = conn.QueryRow(ctx, `SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgrelid='custody_attempt'::regclass AND tgname='zzz_capacity_new_admission'`).Scan(&deferrable, &deferred); e != nil || !deferrable || deferred {
			t.Fatal("history constraint default timing", e)
		}
		if _, e = p.DownTo(ctx, 135); e != nil {
			t.Fatal("history metadata Down", e)
		}
		var shape, trust string
		var absent bool
		if e = conn.QueryRow(ctx, historyAdmissionShape).Scan(&shape); e != nil || shape != originalHistoryAdmission {
			t.Fatal("history Down changed previous guard/trigger definitions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT to_regprocedure('public.capacity_accepted_history_until(uuid,uuid,timestamptz)') IS NULL`).Scan(&absent); e != nil || !absent {
			t.Fatal("history Down retained purpose helper", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("history Down changed trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 135 || to != head {
			t.Fatal("history Up after Down", from, to, e)
		}
		t.Logf("accepted history%d→135→%d: exact old admission function/three triggers and trust retained; helper removed/restored; statement-immediate default", head, head)
	}
	if head == 132 {
		qualifySavedSyscallQueryFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("saved syscall Down", e)
		}
		var restored, constraint, trust string
		if e = conn.QueryRow(ctx, syscallQueryDefinitions).Scan(&restored); e != nil || restored != originalSyscallQueryFunctions {
			t.Fatal("saved syscall Down changed prior query/audit functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='public.context_query_key_binding'::regclass AND conname='context_query_key_binding_binding_check'`).Scan(&constraint); e != nil || constraint != originalKeyBindingConstraint {
			t.Fatal("saved syscall Down changed prior key-child bound", e)
		}
		if e = conn.QueryRow(ctx, `SELECT row_to_json(t)::text FROM fleet_trust t`).Scan(&trust); e != nil || trust != originalTrust {
			t.Fatal("saved syscall Down changed fixture trust/recovery", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("saved syscall Up after Down", from, to, e)
		}
		qualifySavedSyscallQueryFunctions(t, ctx, conn)
		t.Log("saved-syscall132→131→132: exact ten query/audit functions, key-child constraint and trust restored; two units, one read batch, closed metadata/argument source, view, filter and cursor")
	}
	if head == 127 {
		qualifyProfileSummaryQueryFunctions(t, ctx, conn)
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("profile summary Down", e)
		}
		var restored string
		if e = conn.QueryRow(ctx, queryDefinitions).Scan(&restored); e != nil || restored != originalQueryFunctions {
			t.Fatal("summary Down changed prior query/audit functions", e)
		}
		var profileValid bool
		if e = conn.QueryRow(ctx, `SELECT context_query_scope_source_valid('{"NativeType":"pprof"}'::jsonb)`).Scan(&profileValid); e != nil || profileValid {
			t.Fatal("Down kept summary source", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("summary Up after Down", from, to, e)
		}
		qualifyProfileSummaryQueryFunctions(t, ctx, conn)
		t.Log("summary127→126→127: exact query/audit restoration; fixed ten units, one batch, closed source/selection")
	}
	if head == 122 {
		// The extract scope reserves two units and one read batch, admits
		// get_http_headers as its begin tool and needs its record window; a
		// stored pod-status scope keeps one unit, two batches and
		// get_file_excerpt.
		pod := `{"SourceFormat":"asservat-pod-status/v1","DisplayVersion":"approved-pod-status-display/v1","Selection":{"LineStart":1,"MaxLines":200}}`
		extract := `{"NativeType":"httpHeaders","Headers":{"Start":0,"Limit":100},"SourceFormat":"http-response-headers/v1","DisplayVersion":"approved-http-headers-page/v1","Selection":{"LineStart":0,"MaxLines":0}}`
		var podUnits, podBatches, extractUnits, extractBatches int
		var podTool, extractTool string
		var podValid, extractValid, mixedValid, httpInput, contextInput bool
		if e = conn.QueryRow(ctx, `SELECT context_query_units($1::jsonb),context_query_read_batches($1::jsonb),context_query_begin_tool($1::jsonb),context_query_scope_source_valid($1::jsonb),
 context_query_units($2::jsonb),context_query_read_batches($2::jsonb),context_query_begin_tool($2::jsonb),context_query_scope_source_valid($2::jsonb),
 context_query_scope_source_valid($2::jsonb-'Headers'),operation_audit_human_input_valid('get_http_headers','context-query-input/v1'),operation_audit_human_input_valid('get_http_headers','context-input/v1')`, pod, extract).
			Scan(&podUnits, &podBatches, &podTool, &podValid, &extractUnits, &extractBatches, &extractTool, &extractValid, &mixedValid, &httpInput, &contextInput); e != nil ||
			podUnits != 1 || podBatches != 2 || podTool != "get_file_excerpt" || !podValid || extractUnits != 2 || extractBatches != 1 || extractTool != "get_http_headers" || !extractValid || mixedValid || !httpInput || contextInput {
			t.Fatal("http header query functions", e, podUnits, podBatches, podTool, podValid, extractUnits, extractBatches, extractTool, extractValid, mixedValid, httpInput, contextInput)
		}
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("http header query Down", e)
		}
		var restored string
		var helpers int
		if e = conn.QueryRow(ctx, queryDefinitions).Scan(&restored); e != nil || restored != originalQueryFunctions {
			t.Fatal("Down did not restore the exact query functions", e)
		}
		if e = conn.QueryRow(ctx, `SELECT count(*) FROM pg_proc WHERE proname IN ('context_query_units','context_query_read_batches','context_query_begin_tool','context_query_scope_source_valid')`).Scan(&helpers); e != nil || helpers != 0 {
			t.Fatal("Down kept helper functions", helpers, e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("http header query Up after Down", from, to, e)
		}
		t.Log("http header query functions: units/batches/tool/source pinned; Down restored exact functions; Up restored 122")
	}
	if head == 125 {
		qualifyProfileCapacityParity(t, ctx, conn)
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("profile capacity Down", e)
		}
		var restored string
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.capacity_context_protocol_backing(jsonb,jsonb)'::regprocedure)`).Scan(&restored); e != nil || restored != originalCapacityBacking {
			t.Fatal("profile capacity Down changed legacy compiler", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("profile capacity Up", from, to, e)
		}
		qualifyProfileCapacityParity(t, ctx, conn)
	}
	if head == 124 {
		var updated string
		if e = conn.QueryRow(ctx, profileCancelDefinition).Scan(&updated); e != nil || !strings.Contains(updated, "'Profile'") {
			t.Fatal("profile cancellation guard", e)
		}
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("profile cancellation Down", e)
		}
		var restored string
		if e = conn.QueryRow(ctx, profileCancelDefinition).Scan(&restored); e != nil || restored != originalCancellation {
			t.Fatal("profile cancellation Down exact restoration", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != 123 || to != 124 {
			t.Fatal("profile cancellation Up", from, to, e)
		}
	}
	if head == 123 {
		var writerNullable, planNullable bool
		if e = conn.QueryRow(ctx, `SELECT NOT a.attnotnull,NOT b.attnotnull FROM pg_attribute a,pg_attribute b WHERE a.attrelid='public.custody_stream'::regclass AND b.attrelid=a.attrelid AND a.attname='writer_epoch' AND b.attname='plan_digest'`).Scan(&writerNullable, &planNullable); e != nil || !writerNullable || !planNullable {
			t.Fatal("pending stream columns", e)
		}
		var guard, projector, executionGuard string
		if e = conn.QueryRow(ctx, profileDefinitions).Scan(&guard, &projector, &executionGuard); e != nil || !strings.Contains(projector, "pprof") || !strings.Contains(projector, "goTrace") || !strings.Contains(executionGuard, "profilerBusy") {
			t.Fatal("profile processing projector", e)
		}
		// Exercise the actual guard on a fixture table with the exact live column
		// constraints. No fixture row is authority or an acquisition attempt.
		if _, e = conn.Exec(ctx, `CREATE TEMP TABLE profile_stream_probe (LIKE public.custody_stream INCLUDING ALL); CREATE TRIGGER profile_stream_probe_guard BEFORE UPDATE OR DELETE ON profile_stream_probe FOR EACH ROW EXECUTE FUNCTION public.guard_custody_stream()`); e != nil {
			t.Fatal(e)
		}
		attempt, epoch, replacement := custodyID(), custodyID(), custodyID()
		if _, e = conn.Exec(ctx, `INSERT INTO profile_stream_probe(attempt_id,temporary_bytes,temporary_objects,state) VALUES($1,1,2,'{}')`, attempt); e != nil {
			t.Fatal("reserve unbound", e)
		}
		if _, e = conn.Exec(ctx, `UPDATE profile_stream_probe SET state='{"CreateSpent":true}',revision=revision+1 WHERE attempt_id=$1`, attempt); e == nil {
			t.Fatal("unbound journal spent create")
		}
		if _, e = conn.Exec(ctx, `UPDATE profile_stream_probe SET writer_epoch=$2,plan_digest=$3,revision=revision+1 WHERE attempt_id=$1`, attempt, epoch, make([]byte, 32)); e != nil {
			t.Fatal("first exact writer binding", e)
		}
		if _, e = conn.Exec(ctx, `UPDATE profile_stream_probe SET writer_epoch=$2,revision=revision+1 WHERE attempt_id=$1`, attempt, replacement); e == nil {
			t.Fatal("writer replacement accepted")
		}
		if _, e = conn.Exec(ctx, `UPDATE profile_stream_probe SET state='{"CreateSpent":true}',revision=revision+1 WHERE attempt_id=$1`, attempt); e != nil {
			t.Fatal("generic bound journal regression", e)
		}
		if _, e = conn.Exec(ctx, `UPDATE profile_stream_probe SET state='{}',revision=revision+1 WHERE attempt_id=$1`, attempt); e == nil {
			t.Fatal("spent journal reset")
		}
		if _, e = conn.Exec(ctx, `DROP TABLE profile_stream_probe`); e != nil {
			t.Fatal(e)
		}
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("profile Down", e)
		}
		var restoredGuard, restoredProjector, restoredExecutionGuard string
		if e = conn.QueryRow(ctx, profileDefinitions).Scan(&restoredGuard, &restoredProjector, &restoredExecutionGuard); e != nil || restoredGuard != originalStreamGuard || restoredProjector != originalProcessingProjector || restoredExecutionGuard != originalExecutionGuard {
			t.Fatal("profile Down did not restore exact functions", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("profile Up after Down", from, to, e)
		}
		t.Log("profile stream reserve/bind/no-reset guard, native projector and exact function rollback passed")
	}
	if head == 128 {
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("argument authority empty Down", e)
		}
		var restored string
		if e = conn.QueryRow(ctx, argumentAuthorityShape).Scan(&restored); e != nil || restored != originalArgumentAuthority {
			t.Fatal("argument authority Down changed legacy functions/constraints/columns", e)
		}
		if from, to, e = upgrade.Run(ctx); e != nil || from != head-1 || to != head {
			t.Fatal("argument authority Up after Down", from, to, e)
		}
		t.Log("SQL128 empty Down restored exact four functions/session constraints/column shapes; Up reapplied")
	}
	if head == 130 {
		if _, e = p.DownTo(ctx, head-1); e != nil {
			t.Fatal("empty native length Down", e)
		}
		var guard string
		var exists bool
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_context_verification()'::regprocedure), EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='context_verification' AND column_name='native_bytes')`).Scan(&guard, &exists); e != nil || guard != originalNativeLengthGuard || exists {
			t.Fatal("native length Down changed original shape", exists, e)
		}
		if _, e = p.Up(ctx); e != nil {
			t.Fatal("native length Up", e)
		}
	}
	if head == 131 {
		if _, e = p.DownTo(ctx, 130); e != nil {
			t.Fatal("empty raw grant Down", e)
		}
		var shape, guard, auditFunctions string
		if e = conn.QueryRow(ctx, rawAuditFunctions).Scan(&auditFunctions); e != nil || auditFunctions != originalRawAuditFunctions {
			t.Fatal("raw Down changed audit functions", e)
		}
		if e = conn.QueryRow(ctx, rawGrantShape).Scan(&shape); e != nil || shape != originalRawGrantShape {
			t.Fatal("raw Down changed old grant/child shape", e)
		}
		if e = conn.QueryRow(ctx, `SELECT pg_get_functiondef('public.protect_access_grant()'::regprocedure)`).Scan(&guard); e != nil || guard != originalRawGrantGuard {
			t.Fatal("raw Down changed original grant guard", e)
		}
		if _, e = p.Up(ctx); e != nil {
			t.Fatal("raw grant Up", e)
		}
	}
	// A version this binary does not know is refused, not skipped.
	if _, e = conn.Exec(ctx, "INSERT INTO goose_db_version(version_id,is_applied) VALUES($1,true)", head+1); e != nil {
		t.Fatal(e)
	}
	if _, _, e = upgrade.Run(ctx); e == nil {
		t.Fatal("unknown newer history accepted")
	}
	t.Logf("upgrade schema: %d to %d by the schema owner, idempotent, floor %q, unknown history refused", head-1, head, floor)
}
