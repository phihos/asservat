package integration

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real SQL effects and lock waits; the existing fixture supplies synthetic
// live-Pod proof and a test issuer. This does not qualify the installed endpoint.
func qualifyAdmittedWorkerEnrollment(t *testing.T, ctx context.Context, mode string, w value.DownloadWorker, f workerEnrollmentFixture, refresh func() error, admin *pgxpool.Pool) {
	t.Helper()
	var original []byte
	if err := admin.QueryRow(ctx, "SELECT intent_json FROM download_worker WHERE id=$1", w.Intent.ID).Scan(&original); err != nil {
		t.Fatal(err)
	}
	if mode == "enrollment-admitted-detached" {
		// Actually let the original human observation/socket expire. A new
		// worker HTTP request has its own cancellation, never a restamped copy
		// of that expired human authority.
		human, closeHuman := context.WithDeadline(ctx, w.Intent.Authority.ValidUntil)
		defer closeHuman()
		<-human.Done()
		if ctx.Err() != nil || !errors.Is(human.Err(), context.DeadlineExceeded) || w.Intent.Authority.Valid(time.Now()) {
			t.Fatal("original human interval did not expire independently", human.Err(), ctx.Err())
		}
		if err := refresh(); err != nil {
			t.Fatal(err)
		}
		worker, closeWorker := context.WithTimeout(ctx, 30*time.Second)
		defer closeWorker()
		certificate, err := f.enroll(worker, w)
		if err != nil || !certificate.Peer.Valid(time.Now()) || f.issuer.calls.Load() != 1 {
			t.Fatal("admitted worker could not enroll after human disconnect", err, f.issuer.calls.Load())
		}
		var activated bool
		if err = admin.QueryRow(ctx, "SELECT activated_at IS NOT NULL FROM download_worker_certificate WHERE worker_id=$1", w.Intent.ID).Scan(&activated); err != nil || !activated {
			t.Fatal("certificate was not independently activated", activated, err)
		}
		var retained []byte
		if err = admin.QueryRow(ctx, "SELECT intent_json FROM download_worker WHERE id=$1", w.Intent.ID).Scan(&retained); err != nil || !bytes.Equal(original, retained) || w.Intent.Authority.Valid(time.Now()) {
			t.Fatal("identity enrollment rewrote historical human authority", err)
		}
		return
	}

	key, err := mtls.EnrollmentKey(f.csr)
	if err != nil {
		t.Fatal(err)
	}
	proof := func() value.WorkerEnrollmentProof {
		p, err := f.service.Proofs.ReadWorkerEnrollmentProof(ctx, w.Intent.SessionID, w.Intent.ID, key)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	var attempt value.WorkerCertificateAttempt
	activation := mode == "enrollment-admitted-activation-stop"
	if activation {
		enrolled, _, _, err := f.ledger.ClaimWorkerEnrollment(ctx, proof())
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := f.service.Audit.WriteWorkerEnrollment(ctx, enrolled)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.audit.AcknowledgeWorkerEnrollment(ctx, enrolled, receipt); err != nil {
			t.Fatal(err)
		}
		progress, err := f.ledger.PrepareWorkerCertificate(ctx, proof())
		if err != nil || !progress.MaySign {
			t.Fatal("prepare original certificate", err)
		}
		attempt = progress.Attempt
		certificate, err := f.issuer.SignWorkerCertificate(ctx, attempt, f.csr)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.ledger.StoreWorkerCertificate(ctx, attempt, certificate); err != nil {
			t.Fatal(err)
		}
		auditValue := audit.WorkerCertificate{Attempt: attempt, Peer: certificate.Peer}
		receipt, err = f.service.Audit.WriteWorkerCertificate(ctx, auditValue)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.audit.AcknowledgeWorkerCertificate(ctx, auditValue, receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err = refresh(); err != nil {
		t.Fatal(err)
	}
	blocker, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	var blockerPID uint32
	if err = blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "enrollment-admitted-stop-lock", "enrollment-admitted-activation-stop":
		_, err = blocker.Exec(ctx, "UPDATE artifact_download SET state='Cancelled' WHERE id=$1", w.Intent.SessionID)
	case "enrollment-admitted-recovery-lock":
		_, err = blocker.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", w.Intent.Profile.InstallationID)
	case "enrollment-admitted-configuration-lock":
		_, err = blocker.Exec(ctx, "UPDATE download_worker_configuration SET fresh_until=clock_timestamp() WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3", w.Intent.Profile.InstallationID, w.Intent.Profile.ClusterID, w.Intent.Profile.Configuration.UID)
	default:
		t.Fatal("unknown admitted enrollment case", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
	p := proof()
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	role := "worker_enrollment_runtime"
	if activation {
		role = "worker_enrollment_activate_runtime"
	}
	go func() {
		var err error
		if activation {
			_, err = f.activation.ActivateWorkerCertificate(call, p, attempt)
		} else {
			_, _, _, err = f.ledger.ClaimWorkerEnrollment(call, p)
		}
		done <- err
	}()
	joined := false
	defer func() {
		if !joined {
			cancel()
			_ = blocker.Rollback(context.Background())
			<-done
		}
	}()
	wait := time.NewTicker(time.Millisecond)
	defer wait.Stop()
	until := time.NewTimer(750 * time.Millisecond)
	defer until.Stop()
	for {
		var blocked bool
		if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))", role, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case err = <-done:
			joined = true
			t.Fatal("enrollment did not reach the held current-state lock", err)
		case <-until.C:
			t.Fatal("enrollment never waited on exact current-state lock")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-wait.C:
		}
	}
	if err = blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = <-done
	joined = true
	if err == nil || !p.Valid(time.Now()) || ctx.Err() != nil {
		t.Fatal("current refusal after lock was absent or only proof expiry", err, ctx.Err())
	}
	var enrollments, certificates, activated int
	if err = admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM download_worker_enrollment WHERE worker_id=$1),(SELECT count(*) FROM download_worker_certificate WHERE worker_id=$1),(SELECT count(*) FROM download_worker_certificate WHERE worker_id=$1 AND activated_at IS NOT NULL)", w.Intent.ID).Scan(&enrollments, &certificates, &activated); err != nil {
		t.Fatal(err)
	}
	want := 0
	if activation {
		want = 1
	}
	if enrollments != want || certificates != want || activated != 0 || f.issuer.calls.Load() != int64(want) {
		t.Fatal("refused identity effect escaped its transaction", enrollments, certificates, activated, f.issuer.calls.Load())
	}
	var retained []byte
	if err = admin.QueryRow(ctx, "SELECT intent_json FROM download_worker WHERE id=$1", w.Intent.ID).Scan(&retained); err != nil || !bytes.Equal(original, retained) {
		t.Fatal("failed identity effect changed the admitted worker", err)
	}
}

func admittedWorkerEnrollmentCase(mode string) bool {
	return strings.HasPrefix(mode, "enrollment-admitted-")
}
