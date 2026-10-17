package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ownerProofFunction func(context.Context, value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error)

func (f ownerProofFunction) ReadOwnerEnrollmentProof(ctx context.Context, r value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
	return f(ctx, r)
}

type countedOwnerIssuer struct {
	provider app.OwnerCertificateIssuer
	calls    atomic.Int64
}

func (s *countedOwnerIssuer) SignOwnerCertificate(ctx context.Context, p value.OwnerCertificatePermit, csr []byte) (value.IssuedOwnerCertificate, error) {
	s.calls.Add(1)
	return s.provider.SignOwnerCertificate(ctx, p, csr)
}

type interruptedOwnerAudit struct {
	*objectstore.OwnerEnrollmentAuditObjects
	fail bool
}

func (s *interruptedOwnerAudit) WriteOwnerCertificate(ctx context.Context, c audit.OwnerCertificate) (audit.Receipt, error) {
	if s.fail {
		return audit.Receipt{}, errors.New("synthetic audit interruption")
	}
	return s.OwnerEnrollmentAuditObjects.WriteOwnerCertificate(ctx, c)
}

// Composes real SQL/S3/OpenBao with the production coordinator/verifier. Pod
// attestation and initial installation recovery are explicit synthetic inputs;
// native Pod proof is separately exercised by the Kubernetes-owned suite.
func exerciseOwnerRegistration(t *testing.T, f fixture, c value.OwnerConfiguration, b value.OwnerBinding, csrs map[string][]byte, signers map[string]*kms.OwnerCertificateIssuer, v *mtls.OwnerPeerVerifier) {
	t.Helper()
	ctx, end := context.WithTimeout(context.Background(), 45*time.Second)
	defer end()
	l := ownerConfigurationLab(t, ctx, f, c)
	pools := map[string]*pgxpool.Pool{}
	makeLedger := func(role string) *postgres.OwnerEnrollments {
		config := l.writerPool.Config()
		config.ConnConfig.User = "owner_enrollment_" + role + "runtime"
		config.ConnConfig.Password = "synthetic-owner-enrollment"
		if role != "" {
			config.ConnConfig.Password += "-" + role[:len(role)-1]
		}
		pool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pool.Close)
		pools[role] = pool
		s, e := postgres.NewOwnerEnrollments(ctx, pool, c.Pool.InstallationID, c.Pool.ClusterID, c.Pool.NamespaceUID, c.Revision.UID, custodyID)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	ledger, ack, activation, registry, cleanup := makeLedger(""), makeLedger("audit_"), makeLedger("activate_"), makeLedger("read_"), makeLedger("cleanup_")
	auditObjects := &objectstore.OwnerEnrollmentAuditObjects{Store: l.audit.Store, Seal: l.audit.Seal, Open: l.audit.Open}
	actualAudit := &interruptedOwnerAudit{OwnerEnrollmentAuditObjects: auditObjects}
	refresh := func(ctx context.Context) (value.OwnerConfigurationObservation, error) {
		n := time.Now().UTC().Truncate(time.Microsecond)
		if e := renewSyntheticFleetObservation(ctx, l.admin, l.observation, 30*time.Second, false); e != nil {
			return value.OwnerConfigurationObservation{}, e
		}
		o := value.OwnerConfigurationObservation{Configuration: c.Clone(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
		r, ok, e := l.writer.ObserveOwnerConfiguration(ctx, o)
		if e != nil {
			return o, e
		}
		if !ok {
			r, e = l.audit.WriteOwnerConfiguration(ctx, c)
			if e != nil {
				return o, e
			}
			if e = l.ack.AcknowledgeOwnerConfiguration(ctx, c, r); e != nil {
				return o, e
			}
		}
		return l.reader.ReadOwnerConfiguration(ctx)
	}
	rs := custodyID()
	proof := ownerProofFunction(func(ctx context.Context, r value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
		// Native collection starts before its protected configuration read.
		// Preserve that ordering instead of hiding it with a later test start.
		n := time.Now().UTC()
		o, e := refresh(ctx)
		if e != nil {
			return value.OwnerEnrollmentProof{}, e
		}
		key, e := mtls.EnrollmentKey(r.CSRDER)
		if e != nil {
			return value.OwnerEnrollmentProof{}, e
		}
		until := n.Add(5 * time.Second)
		if o.FreshUntil.Before(until) {
			until = o.FreshUntil
		}
		return value.OwnerEnrollmentProof{Binding: r.Binding, Usage: r.Usage, Configuration: o, Pod: "owner-pod", ReplicaSet: "owner-rs", ReplicaSetUID: rs, PublicKeyDigest: key, TokenDigest: artifact.Digest{1}, WorkloadDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}, ObservedAt: n, FreshUntil: until}, nil
	})
	req := value.OwnerEnrollmentRequest{Binding: b, Usage: "server", CSRDER: csrs["server"]}
	issue := &countedOwnerIssuer{provider: signers["server"]}
	service := &app.OwnerEnrollmentCoordinator{Verifier: v, Proofs: proof, Ledger: ledger, Activation: activation, Audit: actualAudit, Acknowledgements: ack, Issuer: issue, Now: time.Now}
	mustProof := func(r value.OwnerEnrollmentRequest) value.OwnerEnrollmentProof {
		p, e := proof(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	p := mustProof(req)
	e, _, _, err := ledger.ClaimOwnerEnrollment(ctx, p)
	if err != nil {
		t.Fatal("claim", err)
	}
	if _, err = ledger.PrepareOwnerCertificate(ctx, p); err == nil {
		t.Fatal("unaudited enrollment signed")
	}
	receipt, err := auditObjects.WriteOwnerEnrollment(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if err = ledger.AcknowledgeOwnerEnrollment(ctx, e, receipt); err == nil {
		t.Fatal("enrollment role acknowledged itself")
	}
	if err = ack.AcknowledgeOwnerEnrollment(ctx, e, receipt); err != nil {
		t.Fatal(err)
	}
	if replay, err := auditObjects.WriteOwnerEnrollment(ctx, e); err != nil || replay != receipt {
		t.Fatal("exact enrollment audit replay", err)
	}
	changedAudit := e
	changedAudit.InitialWorkloadDigest[0] ^= 4
	if _, err = auditObjects.WriteOwnerEnrollment(ctx, changedAudit); err == nil {
		t.Fatal("conflicting enrollment audit reused")
	}
	// Store a real provider result, interrupt audit, then restart the coordinator.
	// Retry must use that exact certificate without spending/signing again.
	actualAudit.fail = true
	if _, err = service.Enroll(ctx, req); err == nil || issue.calls.Load() != 1 {
		t.Fatal("certificate audit failure", err, issue.calls.Load())
	}
	var active int
	if err = l.admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_certificate WHERE enrollment_id=$1 AND activated_at IS NOT NULL", e.ID).Scan(&active); err != nil || active != 0 {
		t.Fatal("unaudited activation", err, active)
	}
	// The stored signing deadline must not be refreshed just to finish audit.
	var deadline time.Time
	if err = l.admin.QueryRow(ctx, "SELECT (convert_from(attempt_json,'UTF8')::jsonb->'Permit'->>'SignBefore')::timestamptz FROM hub_owner_certificate WHERE enrollment_id=$1", e.ID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	select {
	case <-time.After(time.Until(deadline) + 10*time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	actualAudit.fail = false
	service.Ledger = makeLedger("")
	certificate, err := service.Enroll(ctx, req)
	if err != nil || issue.calls.Load() != 1 {
		t.Fatal("resume after provider result", err, issue.calls.Load())
	}
	o, err := registry.ReadOwnerRegistration(ctx, certificate.Certificate)
	if err != nil || o.Enrollment != e || !o.Valid(time.Now()) {
		t.Fatal("registry", err)
	}
	again, err := service.Enroll(ctx, req)
	if err != nil || !bytes.Equal(again.DER, certificate.DER) || issue.calls.Load() != 1 {
		t.Fatal("activated retry signed again", err)
	}
	foreign := certificate.Certificate
	foreign.Binding.ProcessEpoch = custodyID()
	if _, err = registry.ReadOwnerRegistration(ctx, foreign); err == nil {
		t.Fatal("foreign process registry lookup")
	}
	_, differentKey, _ := ed25519.GenerateKey(rand.Reader)
	differentCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, differentKey)
	changed := req
	changed.CSRDER = differentCSR
	if _, err = service.Enroll(ctx, changed); err == nil || issue.calls.Load() != 1 {
		t.Fatal("active process changed key", err)
	}
	// Certificate audit cannot be silently replaced under the same attempt key.
	var attemptBytes []byte
	if err = l.admin.QueryRow(ctx, "SELECT attempt_json FROM hub_owner_certificate WHERE enrollment_id=$1", e.ID).Scan(&attemptBytes); err != nil {
		t.Fatal(err)
	}
	var auditedAttempt value.OwnerCertificateAttempt
	if json.Unmarshal(attemptBytes, &auditedAttempt) != nil {
		t.Fatal("attempt fixture decode")
	}
	exerciseOwnerHistoricalVersions(t, ctx, l, ledger, ack, activation, registry, auditedAttempt, certificate.Certificate, func() value.OwnerEnrollmentProof { return mustProof(req) })
	changedRecord := audit.OwnerCertificate{Attempt: auditedAttempt, Certificate: certificate.Certificate}
	changedRecord.Attempt.WorkloadDigest[0] ^= 8
	if _, err = auditObjects.WriteOwnerCertificate(ctx, changedRecord); err == nil {
		t.Fatal("conflicting certificate audit reused")
	}
	// Wrong-purpose activation and key mutation have no impact on the server leaf.
	clientReq := value.OwnerEnrollmentRequest{Binding: b, Usage: "client", CSRDER: csrs["client"]}
	clientIssue := &countedOwnerIssuer{provider: signers["client"]}
	service.Issuer = clientIssue
	clientCert, err := service.Enroll(ctx, clientReq)
	if err != nil || clientIssue.calls.Load() != 1 {
		t.Fatal("separate client enrollment", err)
	}
	if _, err = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); err != nil {
		t.Fatal(err)
	}
	// Concurrent start preparation consumes exactly one permit. A lost response
	// yields pending progress; neither a fresh adapter nor a retry may re-sign it.
	_, windowEnd, _ := value.OwnerCertificateWindow(time.Now())
	if d := time.Until(windowEnd.Add(-time.Minute)); d > 0 && d < 7*time.Second {
		select {
		case <-time.After(d + 10*time.Millisecond):
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	uncertain := req
	uncertain.Binding.ProcessEpoch = custodyID()
	p = mustProof(uncertain)
	enrollment, _, _, err := ledger.ClaimOwnerEnrollment(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err = auditObjects.WriteOwnerEnrollment(ctx, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if err = ack.AcknowledgeOwnerEnrollment(ctx, enrollment, receipt); err != nil {
		t.Fatal(err)
	}
	var issued atomic.Int64
	var attempt value.OwnerCertificateAttempt
	var mutex sync.Mutex
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			g, e := ledger.PrepareOwnerCertificate(ctx, p)
			if e == nil && g.MaySign {
				issued.Add(1)
				mutex.Lock()
				attempt = g.Attempt
				mutex.Unlock()
			}
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal("concurrent preparation", e)
		}
	}
	if issued.Load() != 1 {
		t.Fatal("duplicate signing permission", issued.Load())
	}
	if _, err = pools[""].Exec(ctx, "DELETE FROM hub_owner_certificate WHERE id=$1", attempt.Permit.ID); err == nil {
		t.Fatal("uncertain spend deleted")
	}
	if _, err = pools[""].Exec(ctx, "UPDATE hub_owner_enrollment SET highest_epoch=-1 WHERE id=$1", enrollment.ID); err == nil {
		t.Fatal("epoch watermark reset")
	}
	// Expire the original proof/permit by waiting on its actual finite deadline.
	delay := time.Until(attempt.Permit.SignBefore) + 10*time.Millisecond
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	p = mustProof(uncertain)
	p.FreshUntil = time.Now().UTC().Add(150 * time.Millisecond)
	retry, err := ledger.PrepareOwnerCertificate(ctx, p)
	if err != nil || !retry.MaySign || retry.Attempt.Permit.Ordinal != 2 || retry.Attempt.Permit.ID == attempt.Permit.ID {
		t.Fatal("bounded second attempt", err)
	}
	select {
	case <-time.After(time.Until(retry.Attempt.Permit.SignBefore) + 10*time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err = ledger.PrepareOwnerCertificate(ctx, mustProof(uncertain)); !errors.Is(err, value.ErrCapacity) {
		t.Fatal("uncertain attempts refilled", err)
	}
	// Admission expiry while blocked on the actual configuration row must fail.
	p = mustProof(req)
	p.FreshUntil = time.Now().UTC().Add(150 * time.Millisecond)
	tx, err := l.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SELECT 1 FROM hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2 FOR UPDATE", c.Pool.InstallationID, c.Pool.ClusterID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, _, e := ledger.ClaimOwnerEnrollment(ctx, p); done <- e }()
	time.Sleep(200 * time.Millisecond)
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("expired blocked proof admitted")
	}
	// Retiring one exact registration immediately fences it without returning
	// capacity. The other purpose and a different process retain their identities.
	if err = cleanup.RetireOwnerEnrollment(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err = registry.ReadOwnerRegistration(ctx, certificate.Certificate); err == nil {
		t.Fatal("retired certificate remained registered")
	}
	if err = cleanup.PruneOwnerEnrollments(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = pools["cleanup_"].Exec(ctx, "DELETE FROM hub_owner_enrollment WHERE id=$1", e.ID); err == nil {
		t.Fatal("retirement refunded live capacity")
	}
	if _, _, _, err = ledger.ClaimOwnerEnrollment(ctx, mustProof(req)); err == nil {
		t.Fatal("retired enrollment revived")
	}
	if _, err = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); err != nil {
		t.Fatal("retirement crossed purposes", err)
	}
	// Existing API observations remain mandatory after activation.
	if err = l.writer.FenceOwnerConfiguration(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); err == nil {
		t.Fatal("source outage did not fence registry")
	}
	if _, err = refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = l.admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", c.Pool.InstallationID); err != nil {
		t.Fatal(err)
	}
	if _, err = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); err == nil {
		t.Fatal("recovery outage did not fence registry")
	}
	if _, err = refresh(ctx); err == nil {
		t.Fatal("source refresh cleared blocked recovery")
	}
	if _, err = l.admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", c.Pool.InstallationID); err != nil {
		t.Fatal(err)
	}
	if restored, err := replaceSyntheticFleetObservationAfterActivation(ctx, l.admin, c.Pool.InstallationID); err != nil {
		t.Fatal(err)
	} else {
		l.observation = restored
	}
	if _, err = refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// SQL permissions prevent using an enrollment/reader credential as an audit,
	// activation, retirement, configuration or recovery writer.
	for _, tc := range []struct {
		role, sql string
		arg       any
	}{
		{"", "UPDATE hub_owner_certificate SET activated_at=clock_timestamp() WHERE enrollment_id=$1", e.ID},
		{"read_", "UPDATE hub_owner_enrollment SET retired_at=clock_timestamp() WHERE id=$1", e.ID},
		{"audit_", "UPDATE hub_owner_certificate SET activated_at=clock_timestamp() WHERE enrollment_id=$1", e.ID},
		{"activate_", "UPDATE hub_owner_enrollment SET audit_receipt_json='x' WHERE id=$1", e.ID},
		{"cleanup_", "UPDATE hub_owner_enrollment SET highest_epoch=0 WHERE id=$1", e.ID},
		{"", "UPDATE hub_owner_configuration SET generation=0 WHERE installation_id=$1", c.Pool.InstallationID},
		{"", "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", c.Pool.InstallationID},
	} {
		_, err = pools[tc.role].Exec(ctx, tc.sql, tc.arg)
		var denied *pgconn.PgError
		if !errors.As(err, &denied) || denied.Code != "42501" {
			t.Fatal("expected SQL privilege denial, not a row-guard rejection", tc.role, tc.sql, err)
		}
	}
	// Exact per-Pod admission includes retired, uncertain and unaudited rows.
	for i := 0; i < value.OwnerRegistrationsPerPod; i++ {
		next := req
		next.Binding.ProcessEpoch = custodyID()
		_, _, _, err = ledger.ClaimOwnerEnrollment(ctx, mustProof(next))
		if errors.Is(err, value.ErrCapacity) {
			break
		}
		if err != nil {
			t.Fatal("registration capacity", err)
		}
	}
	var count int
	if err = l.admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=$1 AND cluster_id=$2 AND pod_uid=$3", b.InstallationID, b.ClusterID, b.PodUID).Scan(&count); err != nil || count != value.OwnerRegistrationsPerPod {
		t.Fatal("bounded pending/retired registrations", err, count)
	}
	next := req
	next.Binding.ProcessEpoch = custodyID()
	if _, _, _, err = ledger.ClaimOwnerEnrollment(ctx, mustProof(next)); !errors.Is(err, value.ErrCapacity) {
		t.Fatal("Pod capacity bypass", err)
	}
	// Seed an expired restored row through the fixture administrator, using only
	// this transaction's disabled triggers. Runtime cleanup must remove it, while
	// retaining all possibly live rows. No runtime role can disable a trigger.
	old := e
	old.ID = custodyID()
	old.Binding.PodUID = custodyID()
	old.Binding.ProcessEpoch = custodyID()
	old.ClaimedAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	_, oldUntil, _ := value.OwnerCertificateWindow(old.ClaimedAt)
	old.InitialHoldUntil = oldUntil.Add(time.Minute)
	if !old.Valid() {
		t.Fatal("invalid expired fixture")
	}
	raw, _ := json.Marshal(old)
	tx, err = l.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL session_replication_role=replica"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO hub_owner_enrollment(id,installation_id,cluster_id,issuer_epoch,pod_uid,process_epoch,usage,enrollment_json,created_at,hold_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", old.ID, old.Binding.InstallationID, old.Binding.ClusterID, old.Binding.IssuerEpoch, old.Binding.PodUID, old.Binding.ProcessEpoch, old.Usage, raw, old.ClaimedAt, old.InitialHoldUntil); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = cleanup.PruneOwnerEnrollments(ctx); err != nil {
		t.Fatal(err)
	}
	if err = l.admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_enrollment WHERE id=$1", old.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired restored registration cleanup", err)
	}
	if _, err = registry.ReadOwnerRegistration(ctx, clientCert.Certificate); err != nil {
		t.Fatal("cleanup deleted current certificate", err)
	}
	t.Log(fmt.Sprintf("owner lifecycle: independent audit/activation, real provider result reuse, uncertain spend, post-lock expiry, retirement, source/recovery denial, roles, bounded %d registrations and expired cleanup passed", value.OwnerRegistrationsPerPod))
}
