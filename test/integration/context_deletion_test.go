package integration

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"slices"
	"sync"
	"testing"
	"time"
)

// Extends the real SQL/S3 producer/publication case. Scope/process/bootstrap and
// effective-cutoff inputs remain synthetic. It qualifies no uncertain-write drain.
func qualifyPositiveContextDeletion(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, bound *objectstore.CustodyStore, keys authorityTestKeys, s captureAdmissionScenario, accepted capture.Accepted) {
	t.Helper()
	newPool := func(role, password string) *pgxpool.Pool { p := poolFor(role, password); t.Cleanup(p.Close); return p }
	cleanupPool := newPool("context_cleanup_runtime", "synthetic-context-cleanup")
	auditPool := newPool("context_cleanup_audit_runtime", "synthetic-context-cleanup-audit")
	finalPool := newPool("context_cleanup_finalize_runtime", "synthetic-context-cleanup-finalize")
	facet := func(p *pgxpool.Pool) *postgres.ContextDeletions {
		v, err := postgres.NewContextDeletions(ctx, p, s.a.RootID, s.a.Recovery.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cleanup, ack, finalize := facet(cleanupPool), facet(auditPool), facet(finalPool)
	if !t.Run("due-pages-pass-persistent-failures-and-wrap", func(t *testing.T) {
		qualifyContextDeletionPaging(t, ctx, cleanupPool, s.a.RootID, s.a.Recovery.InstallationID)
	}) {
		t.FailNow()
	}
	recovery := func() artifact.RecoveryProof {
		p, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	registration := accepted.Expectation.Registration
	loc := registration.Location
	// ADR-205 decision 3: the due list is read with the cleaner's grants only.
	listed := func() bool {
		t.Helper()
		due, err := cleanup.DueContextDeletions(ctx)
		if err != nil || len(due) > 16 {
			t.Fatal("due context deletions", len(due), err)
		}
		return slices.Contains(due, loc)
	}
	if _, err := cleanup.BeginContextDeletion(ctx, loc, recovery()); err == nil {
		t.Fatal("cleanup began before read cutoff")
	}
	if listed() {
		t.Fatal("attempt listed before its effective cutoff")
	}
	if _, err := ack.DueContextDeletions(ctx); err == nil {
		t.Fatal("audit acknowledgement login read custody attempts")
	}
	var writerRows int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM context_writer_completion WHERE attempt_id=$1", loc.AttemptID).Scan(&writerRows); err != nil || writerRows != 1 {
		t.Fatal("missing positive joined writer", writerRows, err)
	}
	denied := func(p *pgxpool.Pool, query string, code string) {
		t.Helper()
		_, err := p.Exec(ctx, query, loc.AttemptID)
		var e *pgconn.PgError
		if !errors.As(err, &e) || e.Code != code {
			t.Fatal("expected exact SQL denial", code, err)
		}
	}
	denied(cleanupPool, "UPDATE context_writer_completion SET closed_at=clock_timestamp() WHERE attempt_id=$1", "42501")
	denied(cleanupPool, "UPDATE context_deletion_checkpoint SET audit_receipt_json=convert_to('{}','UTF8'),audit_acknowledged_at=clock_timestamp() WHERE attempt_id=$1", "42501")
	denied(auditPool, "INSERT INTO context_writer_completion(attempt_id) VALUES($1)", "42501")
	denied(finalPool, "UPDATE context_deletion_checkpoint SET audit_acknowledged_at=clock_timestamp() WHERE attempt_id=$1", "42501")
	denied(cleanupPool, "UPDATE context_deletion_checkpoint SET finalization_xid=pg_current_xact_id() WHERE attempt_id=$1", "42501")
	denied(auditPool, "UPDATE context_deletion_checkpoint SET finalization_xid=pg_current_xact_id() WHERE attempt_id=$1", "42501")
	denied(admin, "UPDATE context_execution SET writer_protocol=NULL WHERE attempt_id=$1", "23514")
	denied(admin, "UPDATE custody_attempt SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1", "23514")
	// The policy input remains synthetic; the actual restrictive retention facet
	// atomically records its immutable decision and advances the guarded overlay.
	retention, err := postgres.NewRetention(ctx, newPool("retention_runtime", "synthetic-retention"), s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Microsecond)
	deleteBy := cutoff.Add(30 * time.Second)
	if registration.DeleteBy.Before(deleteBy) {
		deleteBy = registration.DeleteBy
	}
	decision := retentionTestDecision(t, ctx, retention, loc, cutoff, deleteBy)
	if err = retention.TightenRetention(ctx, decision); err != nil {
		t.Fatal(err)
	}
	if !listed() {
		t.Fatal("attempt past its effective cutoff without a lease not listed")
	}
	work, err := cleanup.BeginContextDeletion(ctx, loc, recovery())
	if err != nil {
		t.Fatal(err)
	}
	if listed() {
		t.Fatal("attempt listed under a live deletion lease")
	}
	genericPool := newPool("custody_runtime", "synthetic-runtime")
	generic, err := postgres.New(ctx, genericPool)
	if err != nil {
		t.Fatal(err)
	}
	if err = generic.FinishDeletion(ctx, work.Deletion); err == nil {
		t.Fatal("generic finalizer bypassed independent checkpoint")
	}
	var charged int64
	if err = admin.QueryRow(ctx, "SELECT charged_objects FROM custody_allocation WHERE id=$1", registration.AllocationID).Scan(&charged); err != nil || charged != 4 {
		t.Fatal("rejected deletion lost charge", charged, err)
	}
	bad := work
	bad.Deletion.Registration.StoreID = custodyID()
	if _, err = cleanup.RecordContextPurge(ctx, bad, time.Now(), recovery()); err == nil {
		t.Fatal("different backend became purge proof")
	}
	if err = bound.PurgeAttempt(ctx, registration); err != nil {
		t.Fatal("actual complete backend purge", err)
	}
	// A positive backend result still cannot cross the original SQL deletion lease.
	// Shortening the lease is an explicit fixture administrator input.
	shortUntil := time.Now().Add(200 * time.Millisecond).UTC().Truncate(time.Microsecond)
	if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=$2 WHERE id=$1", loc.AttemptID, shortUntil); err != nil {
		t.Fatal(err)
	}
	work.Deletion.LeaseUntil = shortUntil
	blocked, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = blocked.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", s.a.RootID); err != nil {
		_ = blocked.Rollback(ctx)
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	beforeWait := recovery()
	purgedAt := time.Now().UTC().Truncate(time.Microsecond)
	go func() { _, e := cleanup.RecordContextPurge(ctx, work, purgedAt, beforeWait); waiting <- e }()
	time.Sleep(time.Until(shortUntil) + 10*time.Millisecond)
	if err = blocked.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-waiting; err == nil {
		t.Fatal("blocking lock renewed original purge lease")
	}
	var positiveRows int
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_deletion_checkpoint WHERE attempt_id=$1", loc.AttemptID).Scan(&positiveRows); err != nil || positiveRows != 0 {
		t.Fatal("expired purge committed", positiveRows, err)
	}
	if !listed() {
		t.Fatal("attempt with an ended deletion lease not listed")
	}
	work, err = cleanup.BeginContextDeletion(ctx, loc, recovery())
	if err != nil {
		t.Fatal(err)
	}
	if err = bound.PurgeAttempt(ctx, registration); err != nil {
		t.Fatal("reconciled complete empty inventory", err)
	}
	result, err := cleanup.RecordContextPurge(ctx, work, time.Now().UTC().Truncate(time.Microsecond), recovery())
	if err != nil {
		t.Fatal(err)
	}
	if err = finalize.FinalizeContextDeletion(ctx, result, recovery()); err == nil {
		t.Fatal("unacknowledged audit released evidence storage")
	}
	if again, found, err := cleanup.ReadContextDeletion(ctx, loc, recovery()); err != nil || !found || again != result {
		t.Fatal("durable purge result changed", err)
	}
	// A successfully purged checkpoint still needs its independent audit. Once
	// its original lease has ended, fair paging must keep that obligation due.
	// The fixture administrator shortens only this lease to avoid a wall wait.
	if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=clock_timestamp()-interval '1 microsecond' WHERE id=$1", loc.AttemptID); err != nil {
		t.Fatal(err)
	}
	if !listed() {
		t.Fatal("purged checkpoint disappeared before audit/finalization")
	}
	page, err := cleanup.DueContextDeletionPage(ctx, postgres.ContextDeletionCursor{})
	if err != nil || !slices.Contains(page.Locations, loc) {
		t.Fatal("fair page lost the retryable purged checkpoint", err)
	}
	// A purged attempt whose audit or release has not finished stays due once
	// its lease ends: Clean reads the checkpoint, skips Begin and resumes the
	// record, acknowledgement and release. Ending the lease is a fixture input.
	if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", loc.AttemptID); err != nil {
		t.Fatal(err)
	}
	if !listed() {
		t.Fatal("purged attempt awaiting its audit not listed for resumption")
	}
	changed := result
	changed.DatabaseOID++
	if err = finalize.FinalizeContextDeletion(ctx, changed, recovery()); err == nil {
		t.Fatal("checkpoint crossed database incarnation")
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := jose.NewContextDeletionSignatures(s.a.RootID, "synthetic-deletion", private, map[string]ed25519.PublicKey{"synthetic-deletion": pub})
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	objects := objectstore.ContextDeletionObjects{Store: store, Seal: keys, Open: keys, Signer: signatures, Verifier: signatures}
	receipt, err := objects.WriteContextDeletion(ctx, result)
	if err != nil {
		t.Fatal("encrypted deletion audit", err)
	}
	if err = ack.AcknowledgeContextDeletion(ctx, result, receipt, recovery()); err != nil {
		t.Fatal(err)
	}
	changedReceipt := receipt
	changedReceipt.SHA256[0]++
	if err = ack.AcknowledgeContextDeletion(ctx, result, changedReceipt, recovery()); err == nil {
		t.Fatal("immutable audit receipt replaced")
	}
	denied(genericPool, "UPDATE context_deletion_checkpoint SET finalization_xid=pg_current_xact_id() WHERE attempt_id=$1", "42501")
	denied(genericPool, "UPDATE custody_attempt SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1", "23514")
	denied(finalPool, "UPDATE custody_attempt SET state='deleted',deleted_at=clock_timestamp() WHERE id=$1", "23514")
	denied(finalPool, "UPDATE context_deletion_checkpoint SET finalization_xid='1'::xid8 WHERE attempt_id=$1", "23514")
	denied(finalPool, "UPDATE context_deletion_checkpoint SET finalization_xid=pg_current_xact_id() WHERE attempt_id=$1", "23514")
	var stranded bool
	if err = admin.QueryRow(ctx, "SELECT finalization_xid IS NOT NULL FROM context_deletion_checkpoint WHERE attempt_id=$1", loc.AttemptID).Scan(&stranded); err != nil || stranded {
		t.Fatal("failed finalization stranded claim", stranded, err)
	}
	if err = generic.FinishDeletion(ctx, work.Deletion); err == nil {
		t.Fatal("generic facet adopted dedicated audited checkpoint")
	}
	originalProof := recovery()
	recoveryChange, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recoveryChange.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", originalProof.InstallationID); err != nil {
		_ = recoveryChange.Rollback(ctx)
		t.Fatal(err)
	}
	finalResult := make(chan error, 1)
	go func() { finalResult <- finalize.FinalizeContextDeletion(ctx, result, originalProof) }()
	select {
	case err = <-finalResult:
		_ = recoveryChange.Rollback(ctx)
		t.Fatal("dedicated finalizer did not wait for current recovery", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err = recoveryChange.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-finalResult; err == nil {
		t.Fatal("finalizer consumed stale recovery snapshot")
	}
	if err = finalize.FinalizeContextDeletion(ctx, result, originalProof); err == nil {
		t.Fatal("recovery fence ignored by deletion finalization")
	}
	if _, err = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", originalProof.InstallationID); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceSyntheticFleetObservationAfterActivation(ctx, admin, originalProof.InstallationID); err != nil {
		t.Fatal(err)
	}
	current := recovery()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- finalize.FinalizeContextDeletion(ctx, result, current) })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal("finalization replay", err)
		}
	}
	var full, replay int64
	if err = admin.QueryRow(ctx, "SELECT ca.charged_objects,cc.charged_full,cc.charged_replay FROM custody_allocation ca JOIN context_control_account cc ON cc.allocation_id=ca.id WHERE ca.id=$1", registration.AllocationID).Scan(&charged, &full, &replay); err != nil || charged != 0 || full != 1 || replay != 1 {
		t.Fatal("wrong release scope", charged, full, replay, err)
	}
	if listed() {
		t.Fatal("finalized attempt still listed")
	}
	denied(admin, "DELETE FROM context_deletion_checkpoint WHERE attempt_id=$1", "23514")
}
