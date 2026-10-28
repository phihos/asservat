package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The owner calls this only after the typed source/permit holder actually stored
// and joined its producer and RecordAPIStoredCompletion acknowledged that result.
// No callback here can invent a writer completion or start a raw recording.
type policyObservationRetirementInput struct {
	Scenario              captureAdmissionScenario
	Accepted              capture.Accepted
	Execution             execution.APIExecution
	Completion            artifact.ContextWriterCompletion
	Permit                collector.ObservationPermit
	AcceptanceID, GrantID string
	Before                *policyObservationGraphSample
}

type policyObservationGraphTable struct {
	Table                                                           string
	Rows, TupleBytes, HeapBytes, IndexBytes, ToastBytes, TotalBytes int64
}

type policyObservationGraphSample struct {
	WAL    string
	Tables []policyObservationGraphTable
}

// Call once before policy acceptance/grant/occurrence/admission for a complete
// phase WAL edge. This raw-pool fixture has no accepted protected root metadata
// qualification. Every result is an UNQUALIFIED component sample, never a bound.
func samplePolicyObservationGraph(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, allocation, pool string) policyObservationGraphSample {
	t.Helper()
	var sample policyObservationGraphSample
	if err := admin.QueryRow(ctx, "SELECT pg_current_wal_insert_lsn()::text").Scan(&sample.WAL); err != nil {
		t.Fatal(err)
	}
	// Closed table/column names only. Row counts/tuple bytes are scoped to this
	// fixture root/allocation; physical sizes cover each ENTIRE shared relation.
	type scopedTable struct{ name, where string }
	tables := []scopedTable{
		{"permission_stream", "r.id=$1::uuid"},
		{"authority_audit", "r.stream_id=$1::uuid"},
		{"custody_pool", "r.id=$3::uuid"},
		{"custody_allocation", "r.id=$2::uuid"},
		{"custody_attempt", "r.allocation_id=$2::uuid"},
		{"custody_copy", "EXISTS(SELECT 1 FROM custody_attempt a WHERE a.id=r.attempt_id AND a.allocation_id=$2::uuid)"},
		{"custody_event", "EXISTS(SELECT 1 FROM custody_attempt a WHERE a.id=r.attempt_id AND a.allocation_id=$2::uuid)"},
	}
	for _, name := range []string{"policy_grant_settings", "policy_source", "policy_acceptance", "access_grant", "policy_grant_attachment", "policy_occurrence", "policy_pod_watermark", "policy_workload_window", "policy_suppression", "context_storage_binding", "context_capture", "context_execution", "context_writer_completion", "policy_observation_session", "context_control_pool", "context_control_account", "context_control_charge", "context_verification", "context_catalog", "context_case_locator", "capture_history_quota", "capture_history_parameter", "retention_decision", "context_deletion_checkpoint"} {
		tables = append(tables, scopedTable{name, "r.root_id=$1::uuid"})
	}
	// One closed UNION keeps all logical counts under one MVCC snapshot and
	// avoids a separate network round trip per relation. No query text is logged.
	statements := make([]string, 0, len(tables))
	for _, table := range tables {
		statements = append(statements, fmt.Sprintf(`SELECT '%s',count(*)::bigint,coalesce(sum(pg_column_size(r)),0)::bigint,
   pg_relation_size('public.%s'::regclass),pg_indexes_size('public.%s'::regclass),
   (SELECT CASE WHEN reltoastrelid=0 THEN 0 ELSE pg_total_relation_size(reltoastrelid) END FROM pg_class WHERE oid='public.%s'::regclass),pg_total_relation_size('public.%s'::regclass)
   FROM public.%s r WHERE %s`, table.name, table.name, table.name, table.name, table.name, table.name, table.where))
	}
	rows, err := admin.Query(ctx, strings.Join(statements, " UNION ALL ")+" ORDER BY 1", root, allocation, pool)
	if err != nil {
		t.Fatal("closed graph sample", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row policyObservationGraphTable
		if err = rows.Scan(&row.Table, &row.Rows, &row.TupleBytes, &row.HeapBytes, &row.IndexBytes, &row.ToastBytes, &row.TotalBytes); err != nil {
			t.Fatal(err)
		}
		sample.Tables = append(sample.Tables, row)
	}
	if err = rows.Err(); err != nil || len(sample.Tables) != len(tables) {
		t.Fatal("incomplete graph sample", len(sample.Tables), err)
	}

	return sample
}

func logPolicyObservationGraph(t *testing.T, ctx context.Context, admin *pgxpool.Pool, phase string, before *policyObservationGraphSample, sample policyObservationGraphSample) {
	t.Helper()
	walLabel := "unavailable"
	if before != nil {
		var wal int64
		if err := admin.QueryRow(ctx, "SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint", sample.WAL, before.WAL).Scan(&wal); err != nil || wal < 0 {
			t.Fatal("graph WAL sample moved backwards", wal, err)
		}
		walLabel = fmt.Sprintf("%dB", wal)
	}
	raw, err := json.Marshal(sample.Tables)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("UNQUALIFIED policy graph sample phase=%s baseline=%t globalWAL=%s tables=%s; root-scoped tuple counts, entire-relation heap/index/TOAST sizes, fixture-inclusive WAL; no protected-root/worst-case/CPU/disk-reclamation claim", phase, before != nil, walLabel, raw)
}

func qualifyPolicyObservationRetirement(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, in policyObservationRetirementInput) {
	t.Helper()
	s, e := in.Scenario, in.Accepted.Expectation
	reg := e.Registration
	if !in.Permit.ValidFinite(in.Permit.StartedAt) || in.Execution.WriterProtocol != artifact.ContextWriterProtocol || in.Execution.Phase != "stored" || in.Execution.Binding.CaptureID != in.Accepted.CaptureID || in.Execution.Binding.AttemptID != reg.Location.AttemptID || !in.Completion.Valid(reg) || in.Completion.Copies != in.Execution.Copies || !in.Completion.StoredAt.Equal(in.Execution.CompletedAt) || in.Permit.Binding.CaptureID != in.Accepted.CaptureID {
		t.Fatal("retirement requires the actual stored/joined original capture")
	}
	previous := in.Before
	sample := func(phase string) {
		snap := samplePolicyObservationGraph(t, ctx, admin, s.a.RootID, reg.AllocationID, s.poolID)
		logPolicyObservationGraph(t, ctx, admin, phase, previous, snap)
		previous = &snap
	}
	sample("stored")
	newFacet := func(role, password string) *postgres.ContextDeletions {
		p := poolFor(role, password)
		t.Cleanup(p.Close)
		facet, err := postgres.NewContextDeletions(ctx, p, s.a.RootID, s.recovery.installation)
		if err != nil {
			t.Fatal(err)
		}
		return facet
	}
	cleaner := newFacet("context_cleanup_runtime", "synthetic-context-cleanup")
	auditor := newFacet("context_cleanup_audit_runtime", "synthetic-context-cleanup-audit")
	finalPool := poolFor("context_cleanup_finalize_runtime", "synthetic-context-cleanup-finalize")
	t.Cleanup(finalPool.Close)
	finalizer, err := postgres.NewContextDeletions(ctx, finalPool, s.a.RootID, s.recovery.installation)
	if err != nil {
		t.Fatal(err)
	}
	proof := func() artifact.RecoveryProof {
		p, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	type balances struct {
		Accepted, Grant, Bytes, Objects, Full, Replay int64
		State                                         string
		Children                                      int64
	}
	read := func() balances {
		var b balances
		err := admin.QueryRow(ctx, `SELECT a.observed_bytes_spent,g.policy_observed_bytes_spent,
   x.charged_bytes,x.charged_objects,c.charged_full,c.charged_replay,p.state,
   (SELECT count(*) FROM policy_observation_session o WHERE o.root_id=a.root_id AND o.capture_id=$5)
   FROM policy_acceptance a JOIN access_grant g ON g.root_id=a.root_id AND g.id=$3
   JOIN custody_allocation x ON x.id=$4 JOIN context_control_account c ON c.root_id=a.root_id AND c.allocation_id=x.id
   JOIN custody_attempt p ON p.id=$6 WHERE a.root_id=$1 AND a.id=$2`, s.a.RootID, in.AcceptanceID, in.GrantID, reg.AllocationID, in.Accepted.CaptureID, reg.Location.AttemptID).Scan(&b.Accepted, &b.Grant, &b.Bytes, &b.Objects, &b.Full, &b.Replay, &b.State, &b.Children)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	original := read()
	if original.Children != 1 || original.Accepted != in.Permit.Credit || original.Grant != in.Permit.Credit || original.Bytes < reg.ReservedBytes() || original.Objects < 4 {
		t.Fatal("missing original observation/charge", original)
	}
	var originalSession int64
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM policy_observation_session
  WHERE root_id=$1 AND capture_id=$2 AND id=$3 AND fence=$4 AND credit=$5 AND max_bytes_per_second=$6
   AND started_at=$7 AND lease_until=$8 AND start_by=$9 AND duration_millis=$10 AND sequence=1`,
		s.a.RootID, in.Accepted.CaptureID, in.Permit.Binding.SessionID, in.Permit.Binding.Fence, in.Permit.Credit, in.Permit.BytesPerSecond,
		in.Permit.StartedAt, in.Permit.LeaseUntil, in.Permit.StartBy, in.Permit.Duration.Milliseconds()).Scan(&originalSession); err != nil || originalSession != 1 {
		t.Fatal("retirement input differs from original SQL session", originalSession, err)
	}
	var writer int64
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM context_writer_completion WHERE root_id=$1 AND attempt_id=$2 AND capture_id=$3 AND stored_at=$4 AND closed_at=$5`, s.a.RootID, reg.Location.AttemptID, in.Accepted.CaptureID, in.Completion.StoredAt, in.Completion.ClosedAt).Scan(&writer); err != nil || writer != 1 {
		t.Fatal("missing actual joined writer acknowledgment", writer, err)
	}
	// The existing retention facet creates a restrictive overlay; original
	// registration and observation lease dates are never rewritten for the test.
	retentionPool := poolFor("retention_runtime", "synthetic-retention")
	t.Cleanup(retentionPool.Close)
	retention, err := postgres.NewRetention(ctx, retentionPool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Microsecond)
	deleteBy := cutoff.Add(30 * time.Second)
	if reg.DeleteBy.Before(deleteBy) {
		deleteBy = reg.DeleteBy
	}
	if err = retention.TightenRetention(ctx, retentionTestDecision(t, ctx, retention, reg.Location, cutoff, deleteBy)); err != nil {
		t.Fatal(err)
	}
	work, err := cleaner.BeginContextDeletion(ctx, reg.Location, proof())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := store.ForCustody(reg.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	if err = bound.PurgeAttempt(ctx, reg); err != nil {
		t.Fatal("actual complete backend purge", err)
	}
	checkpoint, err := cleaner.RecordContextPurge(ctx, work, time.Now().UTC().Truncate(time.Microsecond), proof())
	if err != nil {
		t.Fatal(err)
	}
	purged := original
	purged.State = string(artifact.Deleting)
	if err = finalizer.FinalizeContextDeletion(ctx, checkpoint, proof()); err == nil {
		t.Fatal("unacknowledged deletion released custody")
	}
	if got := read(); got != purged {
		t.Fatal("unacknowledged refusal changed original spend/charges", got, purged)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := jose.NewContextDeletionSignatures(s.a.RootID, "synthetic-policy-deletion", private, map[string]ed25519.PublicKey{"synthetic-policy-deletion": public})
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	objects := objectstore.ContextDeletionObjects{Store: store, Seal: keys, Open: keys, Signer: signatures, Verifier: signatures}
	receipt, err := objects.WriteContextDeletion(ctx, checkpoint)
	if err != nil {
		t.Fatal("actual signed/encrypted deletion audit", err)
	}
	if err = auditor.AcknowledgeContextDeletion(ctx, checkpoint, receipt, proof()); err != nil {
		t.Fatal(err)
	}
	if !time.Now().Before(in.Permit.LeaseUntil) {
		t.Fatal("fixture missed the original early-retirement window")
	}
	if err = finalizer.FinalizeContextDeletion(ctx, checkpoint, proof()); err == nil {
		t.Fatal("acknowledged deletion retired a live observation lease")
	}
	if got := read(); got != purged {
		t.Fatal("early finalization failed to roll back releases", got, purged)
	}
	timer := time.NewTimer(max(0, time.Until(in.Permit.LeaseUntil)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	var expired, acknowledged bool
	if err = admin.QueryRow(ctx, `SELECT clock_timestamp()>=o.lease_until,d.audit_acknowledged_at IS NOT NULL
  FROM policy_observation_session o JOIN context_deletion_checkpoint d ON d.root_id=o.root_id AND d.capture_id=o.capture_id AND d.attempt_id=o.attempt_id
  WHERE o.root_id=$1 AND o.capture_id=$2`, s.a.RootID, in.Accepted.CaptureID).Scan(&expired, &acknowledged); err != nil || !expired || !acknowledged {
		t.Fatal("wrong-transaction test lacks expired lease/real audit ACK", expired, acknowledged, err)
	}
	// Even an expired child with an acknowledged audit needs the finalizer's
	// exact same-transaction claim; no direct DELETE or forged marker is allowed.
	_, err = finalPool.Exec(ctx, "DELETE FROM policy_observation_session WHERE root_id=$1 AND capture_id=$2", s.a.RootID, in.Accepted.CaptureID)
	var sqlError *pgconn.PgError
	if !errors.As(err, &sqlError) || sqlError.Code != "23514" {
		t.Fatal("expired wrong-XID child retirement was not fenced", err)
	}
	if got := read(); got != purged {
		t.Fatal("expired wrong-XID refusal changed original charges", got, purged)
	}
	sample("purged-audited-before-retire")
	if err = finalizer.FinalizeContextDeletion(ctx, checkpoint, proof()); err != nil {
		t.Fatal("actual narrow audited finalizer", err)
	}
	expected := original
	expected.Children = 0
	expected.State = string(artifact.Deleted)
	expected.Bytes -= reg.ReservedBytes()
	expected.Objects -= 4
	if got := read(); got != expected {
		t.Fatal("wrong child/charge/spend retirement", got, expected)
	}
	if err = finalizer.FinalizeContextDeletion(ctx, checkpoint, proof()); err != nil {
		t.Fatal("finalizer replay", err)
	}
	if got := read(); got != expected {
		t.Fatal("finalizer replay refunded original spend", got, expected)
	}
	// Retirement removes the child only. The immutable terminal API receipt
	// still prevents first preparation/retrofit of that same capture.
	var originalExecution int64
	expectedDigest := in.Execution.ExpectationDigest
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM context_execution WHERE root_id=$1 AND capture_id=$2
  AND phase='stored' AND not_before=$3 AND not_after=$4 AND expectation_digest=$5`,
		s.a.RootID, in.Accepted.CaptureID, in.Execution.Binding.NotBefore, in.Execution.Binding.NotAfter, expectedDigest[:]).Scan(&originalExecution); err != nil || originalExecution != 1 {
		t.Fatal("retirement discarded original execution receipt", originalExecution, err)
	}
	sample("retired")
	t.Log("actual observation child 1->0 via complete purge, separate encrypted audit ACK and exact narrow finalization; original accepted/grant observation spend unchanged; physical metadata remains subject to original retention")
}
