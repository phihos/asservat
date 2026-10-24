package integration

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

type syntheticWorkerEnrollmentProof struct{ worker value.DownloadWorker }

func (s syntheticWorkerEnrollmentProof) ReadWorkerEnrollmentProof(_ context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	if s.worker.Intent.ID != worker || s.worker.Intent.SessionID != session {
		return value.WorkerEnrollmentProof{}, artifact.ErrInvalid
	}
	now := time.Now().UTC()
	return value.WorkerEnrollmentProof{Worker: s.worker, PublicKeyDigest: key, TokenDigest: artifact.Digest{1}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

// Test-only provider. It signs real X.509 leaves and passes the product verifier;
// it is not the proposed small-installation CA implementation.
type syntheticWorkerIssuer struct {
	ca       *x509.Certificate
	key      crypto.Signer
	verifier *mtls.KeyPeerVerifier
	calls    atomic.Int64
}

func newSyntheticWorkerIssuer(t *testing.T, installation string) *syntheticWorkerIssuer {
	t.Helper()
	public, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-worker-ca"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: n.Add(-time.Hour), NotAfter: n.Add(24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	v, e := mtls.NewKeyPeerVerifier(roots, installation, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	return &syntheticWorkerIssuer{ca: ca, key: key, verifier: v}
}
func (s *syntheticWorkerIssuer) SignWorkerCertificate(ctx context.Context, a value.WorkerCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	if ctx.Err() != nil || !a.Valid(time.Now()) {
		return value.WorkerCertificate{}, artifact.ErrInvalid
	}
	s.calls.Add(1)
	request, e := x509.ParseCertificateRequest(csr)
	if e != nil {
		return value.WorkerCertificate{}, e
	}
	uri, e := mtls.WorkerCertificateURI(a)
	if e != nil {
		return value.WorkerCertificate{}, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return value.WorkerCertificate{}, e
	}
	leaf := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().UTC().Add(-30 * time.Second), NotAfter: a.CertificateNotAfter, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uri}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, s.ca, request.PublicKey, s.key)
	if e != nil {
		return value.WorkerCertificate{}, e
	}
	return s.verifier.CheckWorkerCertificate(a, csr, der, [][]byte{s.ca.Raw})
}

type workerEnrollmentFixture struct {
	bindings                  *postgres.DownloadWorkers
	service                   *evidence.WorkerEnrollmentCoordinator
	ledger, audit, activation *postgres.WorkerEnrollments
	issuer                    *syntheticWorkerIssuer
	csr                       []byte
}

func newWorkerEnrollmentFixture(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, root string, w value.DownloadWorker, g postgres.DownloadTransactionGuards, store *objectstore.Store, keys authorityTestKeys, authority evidence.DownloadAuthorityGate) workerEnrollmentFixture {
	t.Helper()
	return newWorkerEnrollmentServices(t, ctx, poolFor, root, w.Binding.InstallationID, w.Intent.Profile, syntheticWorkerEnrollmentProof{w}, g, store, keys, authority)
}

// Profile-scoped SQL/issuer services can exist before a worker is dispatched.
// The supplied test-only Pod-proof reader still has to resolve the exact
// subsequently bound worker; this helper allocates no session or worker identity.
func newWorkerEnrollmentServices(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, root, installation string, profile value.DownloadWorkerProfile, proof evidence.WorkerEnrollmentProofReader, g postgres.DownloadTransactionGuards, store *objectstore.Store, keys authorityTestKeys, authority evidence.DownloadAuthorityGate) workerEnrollmentFixture {
	t.Helper()
	var bindings *postgres.DownloadWorkers
	ledger := func(role, password string) *postgres.WorkerEnrollments {
		pool := poolFor(role, password)
		t.Cleanup(pool.Close)
		if role == "worker_enrollment_runtime" {
			var err error
			bindings, err = postgres.NewDownloadWorkers(ctx, pool, root, profile, g)
			if err != nil {
				t.Fatal(err)
			}
		}
		l, e := postgres.NewWorkerEnrollments(ctx, pool, root, profile, custodyID)
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	l := ledger("worker_enrollment_runtime", "synthetic-worker-enrollment")
	a := ledger("worker_enrollment_audit_runtime", "synthetic-worker-enrollment-audit")
	active := ledger("worker_enrollment_activate_runtime", "synthetic-worker-enrollment-activate")
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal(e)
	}
	issuer := newSyntheticWorkerIssuer(t, installation)
	svc := &evidence.WorkerEnrollmentCoordinator{CSR: mtls.EnrollmentProof{}, Proofs: proof, Ledger: l, Activation: active, Audit: &objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: keys, Open: keys}, Acknowledgements: a, Issuer: issuer, Authority: authority, Now: time.Now}
	return workerEnrollmentFixture{bindings, svc, l, a, active, issuer, csr}
}
func (f workerEnrollmentFixture) enroll(ctx context.Context, w value.DownloadWorker) (value.WorkerCertificate, error) {
	return f.service.EnrollAdmitted(ctx, w.Intent.SessionID, w.Intent.ID, f.csr)
}
