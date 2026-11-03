package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL129 component probe, not semantic publication qualification: an administrator
// seeds synthetic accepted/verified metadata inside rollback-only transactions.
// All triggers are enabled for the actual catalog INSERT and its processing
// projection. Full runtime verification must independently validate native bytes.
func qualifyArgumentProcessingSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, root string, accepted capture.Accepted) {
	t.Helper()
	role := narrowRole(t, ctx, admin, "argument_publisher_", "synthetic-argument-publisher", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("context-verify", role)
		if !ok {
			t.Fatal("missing publisher verifier role")
		}
		return grants
	})
	reader := poolFor(role, "synthetic-argument-publisher")
	defer reader.Close()
	id := func(s string) pgtype.UUID {
		var out pgtype.UUID
		if err := out.Scan(s); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if row, err := custodydb.New(reader).ReadPolicyObservation(ctx, custodydb.ReadPolicyObservationParams{RootID: id(root), CaptureID: id(accepted.CaptureID)}); err != nil || row.CaptureID != id(accepted.CaptureID) || row.EventCredit == 0 {
		t.Fatal("scoped publisher cannot read original argument session", err)
	}
	if _, err := reader.Exec(ctx, "UPDATE policy_observation_session SET event_credit=event_credit WHERE false"); err == nil {
		t.Fatal("publisher can mutate original argument credit")
	}
	raw, err := fs.ReadFile(migrations.Files(), "00129_syscall_arguments_processing.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("SQL129 Down missing")
	}
	var originalDefinition string
	if err := admin.QueryRow(ctx, "SELECT pg_get_functiondef('public.project_context_processing()'::regprocedure)").Scan(&originalDefinition); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"arguments", "metadata", "profile", "wrong-class", "wrong-kind", "wrong-mode", "missing-pins", "snapshot-mixture"} {
		t.Run("processing-"+name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := json.Marshal(accepted.Expectation)
			if err != nil {
				t.Fatal(err)
			}
			var e map[string]any
			if err := json.Unmarshal(encoded, &e); err != nil {
				t.Fatal(err)
			}
			e["NativeType"], e["DataClass"] = "syscallArguments", "raw"
			r := e["Recording"].(map[string]any)
			r["Kind"], r["Profile"], r["Arguments"] = "syscallTrace", "arguments", map[string]any{"synthetic": true}
			switch name {
			case "metadata":
				e["NativeType"], e["DataClass"] = "syscallRecords", "metadata"
				r["Profile"] = "metadata"
				delete(r, "Arguments")
			case "profile":
				delete(e, "Recording")
				e["NativeType"] = "pprof"
				e["Profile"] = map[string]any{"Type": "cpu", "MaxBytes": accepted.Expectation.Registration.NativeLimit, "DurationMillis": 1000, "TimeoutMillis": 6000, "Composition": "synthetic"}
			case "wrong-class":
				e["DataClass"] = "metadata"
			case "wrong-kind":
				r["Kind"] = "packetCapture"
			case "wrong-mode":
				r["Profile"] = "metadata"
			case "missing-pins":
				delete(r, "Arguments")
			case "snapshot-mixture":
				e["Snapshot"] = map[string]any{}
			}
			encoded, err = json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			// Synthetic metadata only; no production guard or key authority is
			// bypassed by a runtime credential. Seeding and all effects roll back.
			exec("SET LOCAL session_replication_role=replica")
			exec("UPDATE context_capture SET expectation_json=$2 WHERE id=$1", accepted.CaptureID, encoded)
			exec(`INSERT INTO context_verification(capture_id,root_id,expectation_digest,copies_digest,intent_digest,authority_digest,permission_epoch,permission_sequence)
 SELECT id,root_id,decode(repeat('01',32),'hex'),decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),decode(repeat('04',32),'hex'),permission_epoch,permission_sequence FROM context_capture WHERE id=$1`, accepted.CaptureID)
			if name == "arguments" {
				now := time.Now().UTC().Truncate(time.Microsecond)
				exec(`INSERT INTO context_execution(root_id,capture_id,attempt_id,binding_json,process_json,expectation_digest,not_before,not_after,object_uid,phase,started_at)
 VALUES($1,$2,$3,'{}','{}',decode(repeat('01',32),'hex'),$4,$5,$6,'started',$4)`, root, accepted.CaptureID, accepted.Expectation.Registration.Location.AttemptID, now, now.Add(5*time.Second), custodyID())
			}
			exec("SET LOCAL session_replication_role=origin")
			var before int64
			if err := tx.QueryRow(ctx, "SELECT captures FROM processing_root WHERE root_id=$1", root).Scan(&before); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(ctx, "INSERT INTO context_catalog(artifact_id,capture_id,root_id) VALUES($1,$2,$3)", accepted.Expectation.Registration.Location.ArtifactID, accepted.CaptureID, root)
			want := name == "arguments" || name == "metadata" || name == "profile"
			if !want {
				if err == nil || !strings.Contains(err.Error(), "unqualified processing lineage") {
					t.Fatal("invalid argument lineage not refused", err)
				}
				return
			}
			if err != nil {
				t.Fatal("valid processing lineage", err)
			}
			var after int64
			var count int
			if err := tx.QueryRow(ctx, `SELECT p.captures,(SELECT count(*) FROM context_processing c WHERE c.root_id=p.root_id AND c.capture_id=$2 AND c.origin='capture' AND c.parents='[]') FROM processing_root p WHERE p.root_id=$1`, root, accepted.CaptureID).Scan(&after, &count); err != nil || after != before+1 || count != 1 {
				t.Fatal("processing projection/counter", before, after, count, err)
			}
			if name == "arguments" {
				rows, err := custodydb.New(tx).ListStartedRecordings(ctx, custodydb.ListStartedRecordingsParams{RootID: id(root), StartedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}, Limit: 16})
				if err != nil || len(rows) != 1 || rows[0] != id(accepted.CaptureID) {
					t.Fatal("started argument recording omitted from collect loop", rows, err)
				}
				q := custodydb.New(tx)
				var revision int64
				if err := tx.QueryRow(ctx, "SELECT progress_revision FROM context_capture WHERE id=$1", accepted.CaptureID).Scan(&revision); err != nil {
					t.Fatal(err)
				}
				requested, err := q.RequestSnapshotCancellation(ctx, custodydb.RequestSnapshotCancellationParams{RootID: id(root), ID: id(accepted.CaptureID), SnapshotCancelKey: make([]byte, 32), SnapshotCancelActor: []byte("{}"), ProgressRevision: revision})
				if err != nil || !requested.SnapshotCancelRequestedAt.Valid || requested.SnapshotCancelJoinedAt.Valid {
					t.Fatal("durable argument Stop request", err)
				}
				if _, err = q.RecordUnstartedSnapshotCancellation(ctx, custodydb.RecordUnstartedSnapshotCancellationParams{RootID: id(root), ID: id(accepted.CaptureID)}); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("started argument Stop used no-start shortcut", err)
				}
				joined := pgtype.Timestamptz{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true}
				proof := custodydb.RecordSnapshotCancellationParams{RootID: id(root), ID: id(accepted.CaptureID), SnapshotCancelJoinedAt: joined, SnapshotCancelProof: []byte("{}"), SnapshotCancelProofDigest: make([]byte, 32)}
				exec("SAVEPOINT premature_join")
				if _, err = q.RecordSnapshotCancellation(ctx, proof); err == nil || !strings.Contains(err.Error(), "cancellation lacks joined execution") {
					t.Fatal("request alone became Cancelled", err)
				}
				exec("ROLLBACK TO SAVEPOINT premature_join")
				outcome, err := q.RecordAPIOutcome(ctx, custodydb.RecordAPIOutcomeParams{RootID: id(root), CaptureID: id(accepted.CaptureID), Phase: "cancelled", CompletedAt: joined})
				if err != nil || outcome.Phase != "cancelled" || outcome.CopiesJson != nil {
					t.Fatal("joined argument outcome", err)
				}
				if _, err = q.RecordSnapshotCancellation(ctx, proof); err != nil {
					t.Fatal("joined argument proof", err)
				}
				if _, err = q.RecordSnapshotCancellation(ctx, proof); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("joined proof overwritten", err)
				}
				_, err = tx.Exec(ctx, down)
				if err == nil || !strings.Contains(err.Error(), "retained syscall argument captures") {
					t.Fatal("retained argument downgrade", err)
				}
			} else {
				// Existing metadata and profile rows do not block129 rollback.
				exec(down)
			}
		})
	}
	var restored string
	if err := admin.QueryRow(ctx, "SELECT pg_get_functiondef('public.project_context_processing()'::regprocedure)").Scan(&restored); err != nil || restored != originalDefinition {
		t.Fatal("rollback-only probes changed installed processing definition", err)
	}
	t.Log("SQL129: raw argument lineage, existing profile/metadata publication, started collection, scoped historical reader and retained-argument downgrade refusal")
}
