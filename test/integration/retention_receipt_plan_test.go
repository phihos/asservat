package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The schema56 baseline is retained solely to measure its pre-existing
// all-history completion scan. It is never used as production authority.
const retentionCaughtUpBeforeReceiptIndexes = `SELECT NOT EXISTS (
 SELECT 1 FROM retention_checkpoint c LEFT JOIN retention_catchup j ON j.checkpoint_id=c.id
 WHERE c.root_id=$1 AND c.cluster_id=$2 AND c.namespace_uid=$3
 AND (c.audit_acknowledged_at IS NULL OR j.checkpoint_id IS NULL OR j.completed_at IS NULL
 OR EXISTS(SELECT 1 FROM retention_catchup_effect e JOIN retention_decision d ON d.id=e.decision_id
 WHERE e.checkpoint_id=c.id AND d.audit_acknowledged_at IS NULL))
) AS complete`

func qualifyRetentionReceiptPlans(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	// Use the actual authored query for EXPLAIN and check its Boolean against
	// sqlc's generated method. No planner switches or alternative hot-path SQL.
	raw, err := os.ReadFile("../../migrations/queries/retention_sources.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := strings.Cut(string(raw), "-- name: RetentionSourceCaughtUp :one\n")
	if !ok {
		t.Fatal("actual query missing")
	}
	query, _, ok := strings.Cut(tail, "\n-- name:")
	if !ok {
		t.Fatal("query terminator missing")
	}
	query = strings.TrimSpace(query)
	for _, count := range []int{1, 256, 4096} {
		t.Run(fmt.Sprintf("default-plan-history-%d", count), func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var indexOriginals []retentionReceiptIndexOriginal
			defer func() {
				cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
				defer end()
				if err := tx.Rollback(cleanup); err != nil && !strings.Contains(err.Error(), "closed") {
					t.Error("plan history rollback", err)
				}
				if err := checkRetentionReceiptIndexesRestored(cleanup, admin, indexOriginals); err != nil {
					t.Error("plan index rollback", err)
				}
				// ANALYZE statistics can survive transaction rollback. Restore actual
				// fixture population statistics; do not affect later suite plan choices.
				if _, err := admin.Exec(cleanup, "ANALYZE retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision"); err != nil {
					t.Error("plan fixture statistics cleanup", err)
				}
			}()
			if _, err = tx.Exec(ctx, "SET LOCAL session_replication_role=replica"); err != nil {
				t.Fatal(err)
			}
			root, cluster, epoch := custodyID(), custodyID(), custodyID()
			namespace := "synthetic-query-plan"
			// Synthetic rows exercise the actual indexed SQL shape only. Foreign-key
			// and immutable-row triggers are bypassed by the fixture administrator;
			// no application reader or effect may consume these rows as authority.
			if _, err = tx.Exec(ctx, "INSERT INTO permission_stream(id,epoch,trust_digest,lease_until) VALUES($1,$2,$3,clock_timestamp()+interval '30 seconds')", root, epoch, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "INSERT INTO retention_source(root_id,cluster_id,namespace_uid,hub,protection_digest,epoch,lease_until) VALUES($1,$2,$3,true,$4,$5,clock_timestamp()+interval '30 seconds')", root, cluster, namespace, make([]byte, 32), epoch); err != nil {
				t.Fatal(err)
			}
			type ids struct {
				checkpoint, event, attempt          string
				checkpointReceipt, lifecycleReceipt []byte
			}
			rows := make([]ids, count)
			batch := &pgx.Batch{}
			started := time.Now()
			for i := range rows {
				r := &rows[i]
				r.checkpoint, r.event, r.attempt = custodyID(), custodyID(), custodyID()
				r.checkpointReceipt, _ = json.Marshal(audit.Receipt{Key: audit.RetentionAcceptanceKey(root, r.checkpoint), Version: "synthetic-original", ETag: "synthetic", Bytes: 64, SHA256: artifact.Digest{1}})
				r.lifecycleReceipt, _ = json.Marshal(audit.Receipt{Key: audit.LifecycleKey(root, r.event), Version: "synthetic-original", ETag: "synthetic", Bytes: 64, SHA256: artifact.Digest{1}})
				batch.Queue("INSERT INTO retention_checkpoint(id,root_id,cluster_id,namespace_uid,epoch,sequence,transition_digest,transition_json,record_digest,record_json,audit_acknowledged_at,audit_receipt) VALUES($1,$2,$3,$4,$5,$6,$7,'{}',$7,'{}',clock_timestamp(),$8)", r.checkpoint, root, cluster, namespace, epoch, i+1, make([]byte, 32), r.checkpointReceipt)
				batch.Queue("INSERT INTO retention_catchup(checkpoint_id,completed_at) VALUES($1,clock_timestamp())", r.checkpoint)
				batch.Queue("INSERT INTO retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json,audit_acknowledged_at,audit_receipt_json) VALUES($1,$2,$3,1,clock_timestamp()+interval '20 minutes',clock_timestamp()+interval '30 minutes',clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '10 minutes',$4,$5,clock_timestamp(),$6)", r.event, root, r.attempt, make([]byte, 32), []byte("{}"), r.lifecycleReceipt)
				batch.Queue("INSERT INTO retention_catchup_effect(checkpoint_id,attempt_id,decision_id) VALUES($1,$2,$3)", r.checkpoint, r.attempt, r.event)
			}
			result := tx.SendBatch(ctx, batch)
			if err = result.Close(); err != nil {
				t.Fatal("synthetic plan population", err)
			}
			t.Logf("synthetic indexed population rows=%d elapsed=%s", count, time.Since(started))
			indexOriginals = qualifyRetentionReceiptIndexBackfill(t, ctx, tx, count)
			if _, err = tx.Exec(ctx, "ANALYZE retention_checkpoint,retention_catchup,retention_catchup_effect,retention_decision"); err != nil {
				t.Fatal(err)
			}
			var enabled string
			if err = tx.QueryRow(ctx, "SHOW enable_seqscan").Scan(&enabled); err != nil || enabled != "on" {
				t.Fatal("planner default unavailable", err, enabled)
			}
			parameters := custodydb.RetentionSourceCaughtUpParams{RootID: capacityProjectionUUID(t, root), ClusterID: capacityProjectionUUID(t, cluster), NamespaceUid: namespace}
			check := func(label string, want bool) {
				t.Helper()
				bounded, end := context.WithTimeout(ctx, 5*time.Second)
				defer end()
				got, err := custodydb.New(tx).RetentionSourceCaughtUp(bounded, parameters)
				if err != nil || !got.Valid || got.Bool != want {
					t.Fatal(label, "generated current query", got, want, err)
				}
				var rawValue bool
				if err = tx.QueryRow(bounded, query, root, cluster, namespace).Scan(&rawValue); err != nil || rawValue != got.Bool {
					t.Fatal("authored/generated query mismatch", err)
				}
				var plan []byte
				if err = tx.QueryRow(bounded, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query, root, cluster, namespace).Scan(&plan); err != nil {
					t.Fatal("current default plan", err)
				}
				logRetentionPlan(t, label, plan)
				if count == 4096 && label == "all-valid" {
					for _, index := range []string{"retention_checkpoint_invalid_receipt", "retention_decision_invalid_receipt"} {
						if !strings.Contains(string(plan), `"Index Name": "`+index+`"`) {
							t.Fatal("large-history invalid lookup missed required partial index", index)
						}
					}
				}
			}
			check("all-valid", true)
			var before []byte
			bounded, end := context.WithTimeout(ctx, 5*time.Second)
			err = tx.QueryRow(bounded, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+retentionCaughtUpBeforeReceiptIndexes, root, cluster, namespace).Scan(&before)
			end()
			if err != nil {
				t.Fatal("existing all-history baseline", err)
			}
			logRetentionPlan(t, "schema56-baseline", before)
			setCheckpoint := func(data []byte) {
				t.Helper()
				if _, err := tx.Exec(ctx, "UPDATE retention_checkpoint SET audit_receipt=$2 WHERE id=$1", rows[0].checkpoint, data); err != nil {
					t.Fatal(err)
				}
			}
			setDecision := func(data []byte) {
				t.Helper()
				if _, err := tx.Exec(ctx, "UPDATE retention_decision SET audit_receipt_json=$2 WHERE id=$1", rows[count-1].event, data); err != nil {
					t.Fatal(err)
				}
			}
			setCheckpoint(bytesReplaceReceiptVersion(t, rows[0].checkpointReceipt, ""))
			check("earliest-invalid-checkpoint", false)
			setCheckpoint(rows[0].checkpointReceipt)
			setDecision(bytesReplaceReceiptVersion(t, rows[count-1].lifecycleReceipt, "null"))
			check("latest-invalid-lifecycle", false)
			setDecision([]byte("{"))
			check("malformed-byte-retained", false)
			setDecision(rows[count-1].lifecycleReceipt)
			// A historical cross-root/attempt link must deny even when the root-scoped
			// invalid-receipt index cannot find the foreign decision.
			if _, err = tx.Exec(ctx, "UPDATE retention_decision SET root_id=$2 WHERE id=$1", rows[0].event, custodyID()); err != nil {
				t.Fatal(err)
			}
			check("foreign-decision-root", false)
			if _, err = tx.Exec(ctx, "UPDATE retention_decision SET root_id=$2,attempt_id=$3 WHERE id=$1", rows[0].event, root, custodyID()); err != nil {
				t.Fatal(err)
			}
			check("foreign-decision-attempt", false)
			if _, err = tx.Exec(ctx, "UPDATE retention_decision SET attempt_id=$2 WHERE id=$1", rows[0].event, rows[0].attempt); err != nil {
				t.Fatal(err)
			}
			// An invalid receipt for another exact source does not globally suspend
			// this root. The existing decision->effect uniqueness keeps this join 1:1.
			otherCheckpoint, otherEvent := custodyID(), custodyID()
			otherReceipt, _ := json.Marshal(audit.Receipt{Key: audit.LifecycleKey(root, otherEvent), Version: "", ETag: "synthetic", Bytes: 64, SHA256: artifact.Digest{1}})
			if _, err = tx.Exec(ctx, "INSERT INTO retention_checkpoint(id,root_id,cluster_id,namespace_uid,epoch,sequence,transition_digest,transition_json,record_digest,record_json,audit_acknowledged_at,audit_receipt) SELECT $1,root_id,cluster_id,'other-source',epoch,sequence,transition_digest,transition_json,record_digest,record_json,audit_acknowledged_at,audit_receipt FROM retention_checkpoint WHERE id=$2", otherCheckpoint, rows[0].checkpoint); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "INSERT INTO retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json,audit_acknowledged_at,audit_receipt_json) SELECT $1,root_id,attempt_id,2,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json,audit_acknowledged_at,$3 FROM retention_decision WHERE id=$2", otherEvent, rows[0].event, otherReceipt); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "INSERT INTO retention_catchup_effect(checkpoint_id,attempt_id,decision_id) VALUES($1,$2,$3)", otherCheckpoint, rows[0].attempt, otherEvent); err != nil {
				t.Fatal(err)
			}
			check("invalid-other-source", true)
			var size int64
			if err = tx.QueryRow(ctx, "SELECT pg_relation_size('retention_checkpoint_invalid_receipt')+pg_relation_size('retention_decision_invalid_receipt')").Scan(&size); err != nil {
				t.Fatal(err)
			}
			t.Logf("partial-index physical bytes=%d; includes pre-existing fixture rows and reusable pages", size)
		})
	}
}

func bytesReplaceReceiptVersion(t *testing.T, raw []byte, version string) []byte {
	t.Helper()
	var receipt audit.Receipt
	if json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("synthetic receipt decode")
	}
	receipt.Version = version
	result, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func logRetentionPlan(t *testing.T, label string, raw []byte) {
	t.Helper()
	var plans []map[string]any
	if json.Unmarshal(raw, &plans) != nil || len(plans) != 1 {
		t.Fatal("invalid EXPLAIN JSON")
	}
	t.Logf("%s planning_ms=%v execution_ms=%v", label, plans[0]["Planning Time"], plans[0]["Execution Time"])
	var visit func(map[string]any)
	visit = func(p map[string]any) {
		t.Logf("%s node=%v relation=%v index=%v rows=%v loops=%v removed=%v shared_hit=%v shared_read=%v", label, p["Node Type"], p["Relation Name"], p["Index Name"], p["Actual Rows"], p["Actual Loops"], p["Rows Removed by Filter"], p["Shared Hit Blocks"], p["Shared Read Blocks"])
		if children, ok := p["Plans"].([]any); ok {
			for _, child := range children {
				if node, ok := child.(map[string]any); ok {
					visit(node)
				}
			}
		}
	}
	plan, ok := plans[0]["Plan"].(map[string]any)
	if !ok {
		t.Fatal("missing actual plan")
	}
	visit(plan)
}
