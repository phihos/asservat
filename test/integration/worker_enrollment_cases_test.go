package integration

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"sync"
	"testing"
	"time"
)

func workerEnrollmentCase(t *testing.T, ctx context.Context, mode string, w value.DownloadWorker, f workerEnrollmentFixture, current func() artifact.DownloadAuthority, refresh func() error, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) bool {
	t.Helper()
	if !strings.HasPrefix(mode, "enrollment-") {
		return false
	}
	if mode == "enrollment-channel" {
		qualifyWorkerEnrollmentChannel(t, ctx, w, f)
		return true
	}
	if mode == "enrollment-current-request" {
		qualifyCurrentWorkerEnrollment(t, ctx, w, f, admin)
		return true
	}
	key, e := mtls.EnrollmentKey(f.csr)
	if e != nil {
		t.Fatal(e)
	}
	proof := func() value.WorkerEnrollmentProof {
		p, e := f.service.Proofs.ReadWorkerEnrollmentProof(ctx, w.Intent.SessionID, w.Intent.ID, key)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	claim := func() value.WorkerEnrollment {
		e, _, _, err := f.ledger.ClaimWorkerEnrollment(ctx, proof(), current())
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	acknowledge := func(e value.WorkerEnrollment) {
		r, err := f.service.Audit.WriteWorkerEnrollment(ctx, e)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.audit.AcknowledgeWorkerEnrollment(ctx, e, r); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "enrollment-unaudited" {
		enrollment := claim()
		if _, e = f.ledger.PrepareWorkerCertificate(ctx, proof(), current()); e == nil {
			t.Fatal("unaudited enrollment allowed signing")
		}
		acknowledge(enrollment)
		p := proof()
		progress, e := f.ledger.PrepareWorkerCertificate(ctx, p, current())
		if e != nil || !progress.MaySign {
			t.Fatal("signing attempt", e)
		}
		c, e := f.issuer.SignWorkerCertificate(ctx, progress.Attempt, f.csr)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.ledger.StoreWorkerCertificate(ctx, progress.Attempt, c, current()); e != nil {
			t.Fatal(e)
		}
		if _, e = f.activation.ActivateWorkerCertificate(ctx, proof(), progress.Attempt, current()); e == nil {
			t.Fatal("unaudited certificate activated")
		}
		c2, e := f.enroll(ctx, w)
		if e != nil || c2.Peer != c.Peer || f.issuer.calls.Load() != 1 {
			t.Fatal("audit recovery repeated provider", e, f.issuer.calls.Load())
		}
		return true
	}
	if mode == "enrollment-budget" {
		acknowledge(claim())
		var last value.WorkerCertificateAttempt
		// Unknown outcomes remain spent. Both attempts use deliberately short proof
		// windows; expiry tests do not wait out the full production five seconds.
		for ordinal := 1; ordinal <= 2; ordinal++ {
			p := proof()
			p.FreshUntil = p.ObservedAt.Add(250 * time.Millisecond)
			progress, e := f.ledger.PrepareWorkerCertificate(ctx, p, current())
			if e != nil || !progress.MaySign || progress.Attempt.Ordinal != ordinal {
				t.Fatal("bounded attempt", ordinal, e)
			}
			last = progress.Attempt
			again, e := f.ledger.PrepareWorkerCertificate(ctx, proof(), current())
			if e != nil || again.MaySign || again.Attempt != last {
				t.Fatal("retry re-signed live attempt", e)
			}
			time.Sleep(300 * time.Millisecond)
		}
		if _, e = f.ledger.PrepareWorkerCertificate(ctx, proof(), current()); e == nil {
			t.Fatal("uncertain signing budget refilled")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM download_worker_certificate WHERE worker_id=$1", w.Intent.ID).Scan(&count); e != nil || count != 2 {
			t.Fatal("unbounded attempts", count, e)
		}
		return true
	}
	if mode == "enrollment-expired-lock" {
		acknowledge(claim())
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(ctx)
		if _, e = tx.Exec(ctx, "SELECT id FROM download_worker WHERE id=$1 FOR UPDATE", w.Intent.ID); e != nil {
			t.Fatal(e)
		}
		p := proof()
		p.FreshUntil = p.ObservedAt.Add(250 * time.Millisecond)
		a := current()
		done := make(chan error, 1)
		go func() { _, err := f.ledger.PrepareWorkerCertificate(ctx, p, a); done <- err }()
		time.Sleep(300 * time.Millisecond)
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e == nil {
			t.Fatal("expired proof spent provider attempt after lock")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM download_worker_certificate WHERE worker_id=$1", w.Intent.ID).Scan(&count); e != nil || count != 0 {
			t.Fatal("expired attempt charged", count, e)
		}
		return true
	}
	if mode == "enrollment-parallel" {
		acknowledge(claim())
		p, a := proof(), current()
		var wg sync.WaitGroup
		results := make(chan value.WorkerCertificateProgress, 8)
		errs := make(chan error, 8)
		for range 8 {
			wg.Go(func() { progress, e := f.ledger.PrepareWorkerCertificate(ctx, p, a); results <- progress; errs <- e })
		}
		wg.Wait()
		close(results)
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		calls := 0
		id := ""
		for progress := range results {
			if progress.MaySign {
				calls++
			}
			if id != "" && id != progress.Attempt.ID {
				t.Fatal("parallel workers selected different attempts")
			}
			id = progress.Attempt.ID
		}
		if calls != 1 {
			t.Fatal("provider permit was not single-use", calls)
		}
		return true
	}
	c, e := f.enroll(ctx, w)
	if e != nil {
		t.Fatal(e)
	}
	if mode == "enrollment-replay" {
		again, e := f.enroll(ctx, w)
		if e != nil || again.Peer != c.Peer || string(again.DER) != string(c.DER) || f.issuer.calls.Load() != 1 {
			t.Fatal("enrollment replay changed certificate or re-signed", e)
		}
		return true
	}
	if mode == "enrollment-change-key" {
		_, private, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.Enroll(ctx, "synthetic-reference", w.Intent.SessionID, w.Intent.ID, w.Intent.Authority.Scope, csr); e == nil {
			t.Fatal("process key replaced on retry")
		}
		if f.issuer.calls.Load() != 1 {
			t.Fatal("replacement key reached issuer")
		}
		return true
	}
	if mode == "enrollment-roles" {
		for _, role := range [][2]string{{"worker_enrollment_runtime", "synthetic-worker-enrollment"}, {"worker_enrollment_audit_runtime", "synthetic-worker-enrollment-audit"}, {"worker_enrollment_activate_runtime", "synthetic-worker-enrollment-activate"}} {
			pool := poolFor(role[0], role[1])
			defer pool.Close()
			for _, q := range []string{"UPDATE download_worker_enrollment SET enrollment_json=convert_to('{}','UTF8') WHERE worker_id=$1", "UPDATE download_worker_certificate SET attempt_json=convert_to('{}','UTF8') WHERE worker_id=$1", "DELETE FROM download_worker_enrollment WHERE worker_id=$1", "UPDATE download_worker SET retired_proof_json=convert_to('{}','UTF8') WHERE id=$1"} {
				if _, e = pool.Exec(ctx, q, w.Intent.ID); e == nil {
					t.Fatal("enrollment role rewrote worker or history", role[0], q)
				}
			}
			if role[0] != "worker_enrollment_audit_runtime" {
				if _, e = pool.Exec(ctx, "UPDATE download_worker_certificate SET audit_receipt_json=audit_receipt_json WHERE worker_id=$1", w.Intent.ID); e == nil {
					t.Fatal("enrollment role acknowledged own certificate", role[0])
				}
			}
			if role[0] != "worker_enrollment_activate_runtime" {
				if _, e = pool.Exec(ctx, "UPDATE download_worker_certificate SET activated_at=activated_at WHERE worker_id=$1", w.Intent.ID); e == nil {
					t.Fatal("signing/audit role gained activation", role[0])
				}
			}
		}
		return true
	}
	if mode == "enrollment-audit-reuse" {
		f.service.Audit = rejectRepeatedWorkerAudit{}
		if e = refresh(); e != nil {
			t.Fatal(e)
		}
		if _, e = f.enroll(ctx, w); e != nil {
			t.Fatal("acknowledged enrollment repeated encrypted audit", e)
		}
		return true
	}
	t.Fatal("unknown enrollment case", mode)
	return true
}

type rejectRepeatedWorkerAudit struct{}

func (rejectRepeatedWorkerAudit) WriteWorkerEnrollment(context.Context, value.WorkerEnrollment) (audit.Receipt, error) {
	return audit.Receipt{}, artifact.ErrDownloadUnavailable
}
func (rejectRepeatedWorkerAudit) WriteWorkerCertificate(context.Context, audit.WorkerCertificate) (audit.Receipt, error) {
	return audit.Receipt{}, artifact.ErrDownloadUnavailable
}
