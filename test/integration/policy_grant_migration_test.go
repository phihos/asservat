package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// An owned isolated database retains the actual schema-101 grant trigger and
// row shape before Up. No production authentication or authority is fabricated.
func TestCustodyPolicyGrantMigrationWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Minute)
	defer stop()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := "policy_grant_migration_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("owned migration database cleanup", err)
		}
	}()
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	cfg.MaxConns = 1
	scratch, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	volatility, err := scratch.Query(ctx, `SELECT proname,provolatile::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='pg_catalog' AND proname IN('textsend','convert_to','int4send','sha256') ORDER BY proname`)
	if err != nil {
		t.Fatal(err)
	}
	for volatility.Next() {
		var name, kind string
		if err := volatility.Scan(&name, &kind); err != nil {
			volatility.Close()
			t.Fatal(err)
		}
		t.Logf("actual PostgreSQL function volatility: %s=%s", name, kind)
	}
	err = volatility.Err()
	volatility.Close()
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 101); err != nil {
		t.Fatal("historical schema 101", err)
	}
	id := custodyID()
	if _, err = scratch.Exec(ctx, `INSERT INTO access_grant(id,root_id,kind,preview_id,capture_id,cluster_id,namespace_uid,workload_uid,pod_uid,
 execution_digest,review_digest,data_class,reasons,review,scope,requester_issuer,requester_subject,requester_client,lifetime_seconds,
 idempotency_key,request_digest,requested_at,review_until,decision,approver_issuer,approver_subject,approver_client,decision_reason,
 decision_acr,decision_auth_time,decided_at,decision_key,expires_at,revision)
 SELECT $1,$2,'adHocCapture',$3,$4,$5,'namespace','workload','pod',sha256('{}'::bytea),sha256('review'::bytea),'extract',
 '[{"actionID":"packets","code":"rawBytePredicate"}]'::jsonb,'{}'::bytea,'{}'::bytea,'https://id.example.test','requester','original-client',3600,
 'original-key',sha256('input'::bytea),n-interval '1 minute',n+interval '30 minutes','approved','https://id.example.test','reviewer','review-console','fixture review',
 'fixture-step-up',n-interval '1 minute',n,'decision-key',n+interval '1 hour',2 FROM (SELECT clock_timestamp() AS n) t`,
		id, custodyID(), custodyID(), custodyID(), custodyID()); err != nil {
		t.Fatal("historical approved ad hoc row", err)
	}
	var before, after []byte
	if err = scratch.QueryRow(ctx, `SELECT to_jsonb(g) FROM access_grant g WHERE id=$1`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 102); err != nil {
		t.Fatal("schema 102 Up", err)
	}
	var lane *string
	var inputValid bool
	if err = scratch.QueryRow(ctx, `SELECT operation_audit_lane('request_policy_grant'),operation_audit_human_input_valid('request_policy_grant','context-input/v1')`).Scan(&lane, &inputValid); err != nil || lane == nil || *lane != "normal" || !inputValid {
		t.Fatal("public policy request absent from existing audit envelope", lane, inputValid, err)
	}
	var floor string
	if err = scratch.QueryRow(ctx, `SELECT obj_description('public.goose_db_version'::regclass,'pg_class')`).Scan(&floor); err != nil || floor != "asservat:oldest-binary-schema=102" {
		t.Fatal("old readers must refuse the changed grant semantics", floor, err)
	}
	// Legitimate legacy mutations still work after new generated columns were
	// added. BEFORE triggers must not compare NEW's uncomputed generated values.
	if _, err = scratch.Exec(ctx, `UPDATE access_grant SET revoked_at=clock_timestamp(),revoker_issuer=requester_issuer,revoker_subject=requester_subject,revoker_client=requester_client,revoke_key='revoke-original',revision=3 WHERE id=$1`, id); err != nil {
		t.Fatal("legacy revocation after expansion", err)
	}
	// Compare the actual old shape after Down, including its original anchor,
	// hashes and pool values; only this intentional revocation may differ.
	if _, err = provider.Down(ctx); err != nil {
		t.Fatal("compatible schema 102 Down", err)
	}
	if err = scratch.QueryRow(ctx, `SELECT operation_audit_lane('request_policy_grant'),operation_audit_human_input_valid('request_policy_grant','context-input/v1')`).Scan(&lane, &inputValid); err != nil || lane != nil || inputValid {
		t.Fatal("compatible Down retained unpublished audit command", lane, inputValid, err)
	}
	if err = scratch.QueryRow(ctx, `SELECT to_jsonb(g)-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'] FROM access_grant g WHERE id=$1`, id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	var old map[string]any
	if json.Unmarshal(before, &old) != nil {
		t.Fatal("old row encoding")
	}
	for _, key := range []string{"revoked_at", "revoker_issuer", "revoker_subject", "revoker_client", "revoke_key", "revision"} {
		delete(old, key)
	}
	want, _ := json.Marshal(old)
	var restored map[string]any
	if json.Unmarshal(after, &restored) != nil {
		t.Fatal("restored row encoding")
	}
	got, _ := json.Marshal(restored)
	if !bytes.Equal(want, got) {
		t.Fatal("legacy row changed across Up/Down")
	}
	if err = scratch.QueryRow(ctx, `SELECT obj_description('public.goose_db_version'::regclass,'pg_class')`).Scan(&floor); err != nil || floor != "asservat:oldest-binary-schema=81" {
		t.Fatal("compatible Down did not restore original floor", floor, err)
	}
	// Actual schema-101 historical SQL shapes, not product-authority fixtures:
	// one spent execution, one unknown/unlinked occurrence, one pristine scope.
	// There is deliberately no claim of an exact measured historical byte count.
	legacyRoot := custodyID()
	if _, err = scratch.Exec(ctx, `INSERT INTO permission_stream(id,epoch,trust_digest,lease_until) VALUES($1,$2,sha256('legacy'::bytea),clock_timestamp()+interval '1 hour')`, legacyRoot, custodyID()); err != nil {
		t.Fatal(err)
	}
	legacy := make([]string, 3)
	for i := range legacy {
		legacy[i] = custodyID()
		policy := custodyID()
		if _, err = scratch.Exec(ctx, `INSERT INTO policy_source(root_id,policy_uid,installation_id,cluster_id,namespace_uid,name,generation,spec_digest,resource_version,observed_at,fresh_until,deleted,suspended,collection_digest) SELECT $1,$2,$3,$4,'namespace','legacy',1,sha256('scope'::bytea),'1',n,n+interval '5 seconds',false,false,sha256('collection'::bytea) FROM(SELECT clock_timestamp() n)t`, legacyRoot, policy, custodyID(), custodyID()); err != nil {
			t.Fatal(err)
		}
		spent := int64(0)
		if i == 0 {
			spent = 1
		}
		if _, err = scratch.Exec(ctx, `INSERT INTO policy_acceptance(id,root_id,policy_uid,generation,nonce,scope_digest,request_digest,record_digest,record,accepted_at,executions_spent) VALUES($1,$2,$3,1,$4,sha256('scope'::bytea),sha256('request'::bytea),sha256('record'::bytea),'{"Authority":{"Limits":{"MaxExecutions":100,"MaxBytes":4096,"MaxObservedBytes":8192}}}'::jsonb,clock_timestamp(),$5)`, legacy[i], legacyRoot, policy, custodyID(), spent); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if _, err = scratch.Exec(ctx, `INSERT INTO policy_occurrence(id,root_id,policy_uid,acceptance_id,cluster_id,workload_uid,pod_uid,restarts) VALUES($1,$2,$3,$4,$5,'workload','pod',1)`, custodyID(), legacyRoot, policy, legacy[i], custodyID()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err = provider.UpTo(ctx, 102); err != nil {
		t.Fatal("schema 102 reapply", err)
	}
	for i, id := range legacy {
		var collected, observed int64
		if err = scratch.QueryRow(ctx, `SELECT collected_bytes_spent,observed_bytes_spent FROM policy_acceptance WHERE id=$1`, id).Scan(&collected, &observed); err != nil {
			t.Fatal(err)
		}
		wantCollected, wantObserved := int64(4096), int64(8192)
		if i == 2 {
			wantCollected, wantObserved = 0, 0
		}
		if collected != wantCollected || observed != wantObserved {
			t.Fatal("upgrade replenished unknown historical pools or fenced pristine scope", i, collected, observed)
		}
		if i < 2 {
			var rootID, acceptanceID pgtype.UUID
			if rootID.Scan(legacyRoot) != nil || acceptanceID.Scan(id) != nil {
				t.Fatal("fixture identity")
			}
			count, err := custodydb.New(scratch).SpendPolicyCollectedBytes(ctx, custodydb.SpendPolicyCollectedBytesParams{RootID: rootID, ID: acceptanceID, Bytes: 1})
			if err != nil || count != 0 {
				t.Fatal("production reservation replenished historical output after upgrade", i, err)
			}
		}
	}
	if _, err = provider.Down(ctx); err == nil {
		t.Fatal("rollback discarded conservative historical spend")
	}
}
