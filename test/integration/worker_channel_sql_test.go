package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	workertransport "asservat.local/asservat/internal/transport/worker"
)

type channelSQLProof struct {
	tokens evidence.DownloadPeerToken
	worker value.DownloadWorker
}

func (s channelSQLProof) ReadWorkerEnrollmentProof(ctx context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	token, err := s.tokens.ReadDownloadPeerToken(ctx)
	defer clear(token)
	if err != nil || !bytes.Equal(token, []byte("synthetic.first.token")) {
		return value.WorkerEnrollmentProof{}, artifact.ErrInvalid
	}
	p, err := (syntheticWorkerEnrollmentProof{s.worker}).ReadWorkerEnrollmentProof(ctx, session, worker, key)
	p.TokenDigest = sha256.Sum256(token)
	return p, err
}

// Record the actual client's public CSR only for same-key replay assertions.
type recordedWorkerCSR struct {
	mu     sync.Mutex
	source evidence.WorkerCSRVerifier
	value  []byte
}

func (s *recordedWorkerCSR) EnrollmentKey(raw []byte) (artifact.Digest, error) {
	key, err := s.source.EnrollmentKey(raw)
	if err == nil {
		s.mu.Lock()
		s.value = bytes.Clone(raw)
		s.mu.Unlock()
	}
	return key, err
}

// Composes real TLS/process key -> active control operation -> real authority,
// SQL signing/audit/activation roles and encrypted S3 audit. The Pod proof and
// issuer remain explicit test replacements, not Kubernetes/CA qualification.
func qualifyWorkerEnrollmentChannel(t *testing.T, ctx context.Context, w value.DownloadWorker, f workerEnrollmentFixture) {
	t.Helper()
	target := value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	service := *f.service
	csrRecord := &recordedWorkerCSR{source: service.CSR}
	service.CSR = csrRecord
	op, err := evidence.NewWorkerEnrollmentOperation(parent, service, func(tokens evidence.DownloadPeerToken) (evidence.WorkerEnrollmentProofReader, error) {
		return channelSQLProof{tokens, w}, nil
	}, "synthetic-reference", target, w.Intent.Authority.Scope)
	if err != nil {
		t.Fatal(err)
	}
	router, err := evidence.NewWorkerEnrollmentRouter(ctx, target.InstallationID, f.bindings, time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	route, err := router.Register(parent, op)
	if err != nil {
		t.Fatal("current SQL-bound route", err)
	}
	defer route.Close()
	if _, err = router.Register(parent, op); err == nil {
		t.Fatal("duplicate live owner accepted")
	}
	handler, err := workertransport.NewHandler(target.InstallationID, router, time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	server, roots := channelServer(t, handler)
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(f.issuer.ca)
	newClient := func(target value.WorkerCredentialTarget) *mtls.WorkerCredentials {
		c, err := mtls.NewWorkerCredentials(server.URL, target, roots, issuerRoots, newWorkerChannelFixture(t), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		return c
	}
	bad := target
	bad.WorkerID = custodyID()
	if err := newClient(bad).Enroll(ctx); err == nil || f.issuer.calls.Load() != 0 {
		t.Fatal("worker selected another operation", err)
	}
	c := newClient(target)
	if err := c.Enroll(ctx); err != nil {
		t.Fatal(err)
	}
	cert := channelCert(t, c)
	peer, err := c.Peer()
	if err != nil {
		t.Fatal(err)
	}
	if peer.Certificate != artifact.Digest(sha256.Sum256(cert.Certificate[0])) || f.issuer.calls.Load() != 1 {
		t.Fatal("certificate not issued/installed exactly once")
	}
	csrRecord.mu.Lock()
	csr := bytes.Clone(csrRecord.value)
	csrRecord.mu.Unlock()
	delivery, err := router.BeginWorkerEnrollment(ctx, target.InstallationID, target.SessionID, target.WorkerID, []byte("synthetic.first.token"), csr)
	if err != nil {
		t.Fatal("same-key routed replay", err)
	}
	route.Close()
	select {
	case <-delivery.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("closing owner did not cancel delivery")
	}
	if _, err = router.Register(parent, op); err == nil {
		t.Fatal("response still open but route capacity refunded")
	}
	delivery.Close()
	next, err := router.Register(parent, op)
	if err != nil {
		t.Fatal("finished owner slot unavailable", err)
	}
	defer next.Close()
	route.Close() // A delayed cleanup of the old owner cannot remove next.
	replay, err := router.BeginWorkerEnrollment(ctx, target.InstallationID, target.SessionID, target.WorkerID, []byte("synthetic.first.token"), csr)
	if err != nil {
		t.Fatal("new active owner lost after old close", err)
	}
	if replay.Certificate().Peer != peer || f.issuer.calls.Load() != 1 {
		t.Fatal("routing replay changed certificate or repeated signing")
	}
	replay.Close()
	cancel()
	if err := newClient(target).Enroll(ctx); err == nil || f.issuer.calls.Load() != 1 {
		t.Fatal("cancelled human operation authorized enrollment", err)
	}
}
