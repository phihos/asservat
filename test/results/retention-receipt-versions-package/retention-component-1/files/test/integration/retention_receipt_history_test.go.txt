package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This fixture-only administrator simulates retained legacy history. Runtime
// roles cannot perform this mutation. Compare complete stored receipt/row bytes,
// including PostgreSQL's JSONB rendering, and restore the exact original value.
func withHistoricalRetentionReceipt(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, event, kind, version string, check func()) {
	t.Helper()
	var read, write string
	switch kind {
	case "checkpoint":
		read = "SELECT c.audit_receipt, row_to_json(c)::text FROM retention_checkpoint c WHERE root_id=$1 AND id=$2"
		write = "UPDATE retention_checkpoint SET audit_receipt=$3 WHERE root_id=$1 AND id=$2"
	case "lifecycle":
		read = "SELECT d.audit_receipt_json, row_to_json(d)::text FROM retention_decision d WHERE root_id=$1 AND id=$2"
		write = "UPDATE retention_decision SET audit_receipt_json=$3 WHERE root_id=$1 AND id=$2"
	default:
		t.Fatal("unknown fixed receipt purpose")
	}
	readStored := func(readCtx context.Context) ([]byte, string) {
		t.Helper()
		var raw []byte
		var row string
		if err := admin.QueryRow(readCtx, read, root, event).Scan(&raw, &row); err != nil {
			t.Fatal("read exact retained receipt", err)
		}
		return raw, row
	}
	set := func(writeCtx context.Context, raw []byte) {
		t.Helper()
		tx, err := admin.Begin(writeCtx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(writeCtx)
		if _, err = tx.Exec(writeCtx, "SET LOCAL session_replication_role=replica"); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(writeCtx, write, root, event, raw)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("set original fixture receipt", err)
		}
		if err = tx.Commit(writeCtx); err != nil {
			t.Fatal(err)
		}
	}
	original, originalRow := readStored(ctx)
	var receipt audit.Receipt
	if json.Unmarshal(original, &receipt) != nil {
		t.Fatal("original receipt decode")
	}
	valid := receipt.ValidRetentionAcceptance(root, event)
	if kind == "lifecycle" {
		valid = receipt.ValidLifecycle(root, event)
	}
	if !valid {
		t.Fatal("original fixture receipt is not current")
	}
	receipt.Version = version
	mutated, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Fixture cleanup may restore only the exact original row after a failed
		// or cancelled case; it grants no operation a new authority interval.
		cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		set(cleanup, original)
		restored, row := readStored(cleanup)
		if !bytes.Equal(original, restored) || row != originalRow {
			t.Error("exact historical receipt/row restoration failed")
		}
	}()
	set(ctx, mutated)
	baseline, baselineRow := readStored(ctx)
	var stored audit.Receipt
	if json.Unmarshal(baseline, &stored) != nil || stored != receipt {
		t.Fatal("database did not retain intended full receipt")
	}
	check()
	after, row := readStored(ctx)
	if !bytes.Equal(after, baseline) || row != baselineRow {
		t.Fatal("denial changed retained history")
	}
}

func qualifyRetentionReceiptHistory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, setup func(*testing.T) (*postgres.RetentionSources, *postgres.RetentionSources, app.RetentionTransition), advance func(*testing.T, *postgres.RetentionSources, app.RetentionCheckpoint, int64, string) (app.RetentionTransition, app.RetentionCheckpoint)) {
	readPool := poolFor("retention_source_read_runtime", "synthetic-retention-source-read")
	defer readPool.Close()
	catchPool := poolFor("retention_catchup_runtime", "synthetic-retention-catchup")
	defer catchPool.Close()
	for _, position := range []string{"earliest", "latest"} {
		for _, version := range []string{"", "null"} {
			label := version
			if label == "" {
				label = "empty"
			}
			t.Run("retention-current-history-"+position+"-"+label, func(t *testing.T) {
				source, auditor, request := setup(t)
				first, err := source.AcceptRetention(ctx, request)
				if err != nil {
					t.Fatal(err)
				}
				nextRequest, latest := advance(t, source, first, 3600, "101")
				root, ref := request.Fence.RootID, request.Fence.Source
				worker, err := postgres.NewRetention(ctx, catchPool, root)
				if err != nil {
					t.Fatal(err)
				}
				reader, err := postgres.NewRetentionSources(ctx, readPool, root)
				if err != nil {
					t.Fatal(err)
				}
				publisher := app.RetentionAcceptancePublisher{Journal: auditor, Writer: &objectstore.RetentionAcceptanceObjects{Store: store, Seal: keys, Open: keys}}
				if err = publisher.Publish(ctx, 64); err != nil {
					t.Fatal(err)
				}
				// Retained old receipts remain parseable for restrictive work. This
				// does not make them current receipts or renew either source interval.
				withHistoricalRetentionReceipt(t, ctx, admin, root, first.Record.ID, "checkpoint", version, func() {
					old, err := source.AcceptRetention(ctx, request)
					if err != nil || !old.Audited {
						t.Fatal("structural earlier replay", err)
					}
					for range 2 {
						page, err := worker.ReconcileRetentionPage(ctx, ref, 1)
						if err != nil || !page.Complete {
							t.Fatal("historical catch-up was blocked", page, err)
						}
					}
				})
				list := latest.Transition.List
				now := time.Now().UTC().Truncate(time.Microsecond)
				list.Snapshot.ObservedAt, list.Snapshot.FreshUntil = now, now.Add(5*time.Second)
				fence := request.Fence
				fence.Sequence = latest.Record.Sequence
				if err = source.ObserveRetention(ctx, app.RetentionObservation{Fence: fence, List: list, Protection: privacy.SourceProtection{SourceClusterID: ref.ClusterID, ControlNamespaceUID: ref.ControlNamespaceUID, Digest: ref.ProtectionDigest, ObservedAt: now, FreshUntil: list.Snapshot.FreshUntil}}); err != nil {
					t.Fatal(err)
				}
				baseline, err := reader.AcceptedRetentionSource(ctx, root, ref)
				if err != nil || !baseline.Ready {
					t.Fatal("original source unavailable", err)
				}
				target, replay := first, request
				if position == "latest" {
					target, replay = latest, nextRequest
				}
				withHistoricalRetentionReceipt(t, ctx, admin, root, target.Record.ID, "checkpoint", version, func() {
					if _, err := reader.AcceptedRetentionSource(ctx, root, ref); err == nil {
						t.Fatal("unversioned retained checkpoint authorized current source")
					}
					old, err := source.AcceptRetention(ctx, replay)
					if err != nil || !old.Audited || old.Record.ID != target.Record.ID {
						t.Fatal("structural exact replay lost", err)
					}
					if !time.Now().Before(baseline.FreshUntil) {
						t.Fatal("negative outlived original observation")
					}
				})
				restored, err := reader.AcceptedRetentionSource(ctx, root, ref)
				if err != nil || !restored.Ready || !restored.FreshUntil.Equal(baseline.FreshUntil) {
					t.Fatal("exact restored source lost original interval", err)
				}
			})
		}
	}
}

func qualifyRetentionLifecycleReceiptHistory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, reader *postgres.RetentionSources, root string, ref privacy.PolicySourceRef, refresh func(*testing.T)) {
	t.Helper()
	var event string
	if err := admin.QueryRow(ctx, "SELECT d.id::text FROM retention_decision d JOIN retention_catchup_effect e ON e.decision_id=d.id JOIN retention_checkpoint c ON c.id=e.checkpoint_id WHERE d.root_id=$1 AND c.root_id=$1 AND c.cluster_id=$2 AND c.namespace_uid=$3 ORDER BY c.sequence,d.id LIMIT 1", root, ref.ClusterID, ref.ControlNamespaceUID).Scan(&event); err != nil {
		t.Fatal("original completed lifecycle effect", err)
	}
	for _, version := range []string{"", "null"} {
		label := version
		if label == "" {
			label = "empty"
		}
		t.Run("retention-current-earlier-lifecycle-"+label, func(t *testing.T) {
			refresh(t)
			original, err := reader.AcceptedRetentionSource(ctx, root, ref)
			if err != nil || !original.Ready {
				t.Fatal("current actual source", err)
			}
			withHistoricalRetentionReceipt(t, ctx, admin, root, event, "lifecycle", version, func() {
				if _, err := reader.AcceptedRetentionSource(ctx, root, ref); err == nil {
					t.Fatal("unversioned earlier catch-up effect authorized current source")
				}
				if !time.Now().Before(original.FreshUntil) {
					t.Fatal("negative outlived original observation")
				}
			})
			restored, err := reader.AcceptedRetentionSource(ctx, root, ref)
			if err != nil || !restored.Ready || !restored.FreshUntil.Equal(original.FreshUntil) {
				t.Fatal("exact lifecycle restore changed original observation", err)
			}
		})
	}
	for _, field := range []string{"root", "attempt"} {
		t.Run("retention-current-lifecycle-foreign-"+field, func(t *testing.T) {
			refresh(t)
			original, err := reader.AcceptedRetentionSource(ctx, root, ref)
			if err != nil || !original.Ready {
				t.Fatal("current actual source", err)
			}
			withHistoricalRetentionDecisionIdentity(t, ctx, admin, root, event, field, func() {
				if _, err := reader.AcceptedRetentionSource(ctx, root, ref); err == nil {
					t.Fatal("foreign historical lifecycle identity authorized readiness")
				}
				if !time.Now().Before(original.FreshUntil) {
					t.Fatal("negative outlived original observation")
				}
			})
			restored, err := reader.AcceptedRetentionSource(ctx, root, ref)
			if err != nil || !restored.Ready || !restored.FreshUntil.Equal(original.FreshUntil) {
				t.Fatal("exact identity restore changed original observation", err)
			}
		})
	}
}

// Purpose-fixed fixture corruption for the two identity columns already joined
// by readiness. It neither changes the accepted source nor creates an audit.
func withHistoricalRetentionDecisionIdentity(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, event, field string, check func()) {
	t.Helper()
	read := func(readCtx context.Context) (string, string, string) {
		t.Helper()
		var gotRoot, attempt, row string
		if err := admin.QueryRow(readCtx, "SELECT d.root_id::text,d.attempt_id::text,row_to_json(d)::text FROM retention_decision d WHERE id=$1", event).Scan(&gotRoot, &attempt, &row); err != nil {
			t.Fatal(err)
		}
		return gotRoot, attempt, row
	}
	originalRoot, originalAttempt, originalRow := read(ctx)
	if originalRoot != root {
		t.Fatal("wrong original lifecycle root")
	}
	var write, original string
	switch field {
	case "root":
		write = "UPDATE retention_decision SET root_id=$2 WHERE id=$1"
		original = originalRoot
	case "attempt":
		write = "UPDATE retention_decision SET attempt_id=$2 WHERE id=$1"
		original = originalAttempt
	default:
		t.Fatal("unknown fixed lifecycle identity")
	}
	set := func(writeCtx context.Context, value string) {
		t.Helper()
		tx, err := admin.Begin(writeCtx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(writeCtx)
		if _, err = tx.Exec(writeCtx, "SET LOCAL session_replication_role=replica"); err != nil {
			t.Fatal(err)
		}
		tag, err := tx.Exec(writeCtx, write, event, value)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("fixture lifecycle identity", err)
		}
		if err = tx.Commit(writeCtx); err != nil {
			t.Fatal(err)
		}
	}
	replacement := custodyID()
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		set(cleanup, original)
		_, _, restored := read(cleanup)
		if restored != originalRow {
			t.Error("exact lifecycle identity restoration failed")
		}
	}()
	set(ctx, replacement)
	changedRoot, changedAttempt, baseline := read(ctx)
	if (field == "root" && (changedRoot != replacement || changedAttempt != originalAttempt)) || (field == "attempt" && (changedAttempt != replacement || changedRoot != originalRoot)) {
		t.Fatal("database did not retain intended original identity change")
	}
	check()
	_, _, after := read(ctx)
	if after != baseline {
		t.Fatal("denial changed historical lifecycle identity")
	}
}

func qualifyRetentionAdmissionReceiptHistory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	for _, version := range []string{"", "null"} {
		label := version
		if label == "" {
			label = "empty"
		}
		t.Run("retention-current-admitted-effect-"+label, func(t *testing.T) {
			s := create(t, 1)
			original := s.a.Plan.Input.Retention.Proof
			if !original.Valid(time.Now()) {
				t.Fatal("original admitted retention proof unavailable")
			}
			withHistoricalRetentionReceipt(t, ctx, admin, s.a.RootID, s.retention.checkpoint.Record.ID, "checkpoint", version, func() {
				if _, err := s.s.AdmitContext(ctx, s.a); err == nil {
					t.Fatal("old retained receipt authorized final admission transaction")
				}
				var count int
				if err := admin.QueryRow(ctx, "SELECT count(*) FROM context_capture WHERE root_id=$1 AND id=$2", s.a.RootID, s.a.Plan.Input.CaptureID).Scan(&count); err != nil || count != 0 {
					t.Fatal("denied effect persisted capture", count, err)
				}
				if !original.Valid(time.Now()) {
					t.Fatal("negative outlived original admitted proof")
				}
			})
			if _, err := s.s.AdmitContext(ctx, s.a); err != nil {
				t.Fatal("exact restore rejected original admitted authority", err)
			}
		})
	}
}
