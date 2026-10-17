package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// Only this fixture's accepted connector source, enrollment ledger and CA are
// synthetic. Its credential owner generates the actual two process keys. The
// process proof below comes from the real Pod-bound TokenReview/native guard.
// This does not qualify SQL connector enrollment or a deployed connector image.
type contextStartConnectorFixture struct {
	mu                   sync.Mutex
	profile              fleet.ConnectorCredentialProfile
	proof                app.ConnectorProcessProofReader
	clientCA, serverCA   *x509.Certificate
	clientKey, serverKey *ecdsa.PrivateKey
	process              fleet.ConnectorCredentialProcess
	issued               map[string]fleet.IssuedConnectorCredential
	origins              map[artifact.Digest]fleet.ConnectorProcessIdentity
}

func (f *contextStartConnectorFixture) ReadConnectorIdentitySource(ctx context.Context) (fleet.ConnectorIdentitySource, error) {
	if ctx.Err() != nil {
		return fleet.ConnectorIdentitySource{}, ctx.Err()
	}
	n := time.Now().UTC()
	return fleet.ConnectorIdentitySource{Observation: fleet.ConnectorCredentialObservation{Profile: f.profile.Clone(), Backing: fleet.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{1}, SourceDigest: artifact.Digest{2}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Roles: fleet.ConnectorIdentityRoles{Source: "fixture_source", Journal: "fixture_journal", Acknowledgement: "fixture_ack", Cleanup: "fixture_cleanup", Verifier: "fixture_verify", Finalizer: "fixture_final"}}, nil
}
func (f *contextStartConnectorFixture) Enroll(ctx context.Context, id string, r fleet.ConnectorProcessRequest) (fleet.ConnectorCredentialProcess, error) {
	p, e := f.proof.ReadConnectorProcessProof(ctx, r)
	if e != nil || !p.Valid(time.Now()) {
		return fleet.ConnectorCredentialProcess{}, fleet.ErrDenied
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.process.Attested != nil {
		if *f.process.Attested != r.Process {
			return fleet.ConnectorCredentialProcess{}, fleet.ErrDenied
		}
		return f.process, nil
	}
	n := time.Now().UTC().Truncate(time.Second)
	f.process = fleet.ConnectorCredentialProcess{Attested: &r.Process, Binding: r.Process.Binding, ClientKeyDigest: p.ClientKeyDigest, ServerKeyDigest: p.ServerKeyDigest, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute), RunUntil: n.Add(33 * time.Minute)}
	return f.process, nil
}
func (f *contextStartConnectorFixture) IssueProcess(ctx context.Context, id, usage string, r fleet.ConnectorProcessRequest) (fleet.IssuedConnectorCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.issued[id]; ok {
		return old.Clone(), nil
	}
	if ctx.Err() != nil || f.process.Attested == nil || *f.process.Attested != r.Process {
		return fleet.IssuedConnectorCredential{}, fleet.ErrDenied
	}
	csr, ca, key, eku, name := r.ClientCSRDER, f.clientCA, f.clientKey, x509.ExtKeyUsageClientAuth, ""
	if usage == "server" {
		csr, ca, key, eku, name = r.ServerCSRDER, f.serverCA, f.serverKey, x509.ExtKeyUsageServerAuth, f.profile.ServerName
	} else if usage != "client" {
		return fleet.IssuedConnectorCredential{}, fleet.ErrDenied
	}
	q, e := x509.ParseCertificateRequest(csr)
	if e != nil {
		return fleet.IssuedConnectorCredential{}, e
	}
	kd, e := mtls.EnrollmentKey(csr)
	if e != nil {
		return fleet.IssuedConnectorCredential{}, e
	}
	_, until, e := f.process.Window(time.Now())
	if e != nil {
		return fleet.IssuedConnectorCredential{}, e
	}
	uri, e := mtls.PeerURI(r.Process.Binding)
	if e != nil {
		return fleet.IssuedConnectorCredential{}, e
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(len(f.issued) + 1)), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{uri}, NotBefore: f.process.ClaimedAt.Add(-time.Second), NotAfter: until}
	if name != "" {
		tmpl.DNSNames = []string{name}
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, q.PublicKey, key)
	if e != nil {
		return fleet.IssuedConnectorCredential{}, e
	}
	out := fleet.IssuedConnectorCredential{Certificate: fleet.ConnectorCredentialCertificate{Binding: r.Process.Binding, Usage: usage, ServerName: name, Digest: sha256.Sum256(der), PublicKeyDigest: kd, NotBefore: tmpl.NotBefore, NotAfter: until}, DER: der, ChainDER: [][]byte{ca.Raw}}
	f.issued[id] = out
	f.origins[out.Certificate.Digest] = r.Process
	return out.Clone(), nil
}
func (f *contextStartConnectorFixture) ConnectorLeafRegistration(ctx context.Context, c fleet.ConnectorCredentialCertificate) (app.ConnectorLeafRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := time.Now().UTC()
	origin, ok := f.origins[c.Digest]
	if ctx.Err() != nil || !ok || !c.Valid(n) {
		return app.ConnectorLeafRegistration{}, fleet.ErrDenied
	}
	return app.ConnectorLeafRegistration{Certificate: c, Process: origin, Revision: f.profile.Revision, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}

type contextStartPodToken []byte

func (t contextStartPodToken) ReadConnectorPodToken(context.Context) ([]byte, error) {
	return append([]byte(nil), t...), nil
}
