package mtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// WorkerCredentials owns one process key, never a human token, master key or
// provider credential. It does not authorize evidence access or replace the
// current activated-certificate registry and dedicated Pod-token checks.
type WorkerCredentials struct {
	mu           sync.Mutex
	target       value.WorkerCredentialTarget
	now          func() time.Time
	tokens       evidence.DownloadPeerToken
	verifier     *KeyPeerVerifier
	client       *http.Client
	endpoint     string
	key          *ecdsa.PrivateKey
	csr          []byte
	cert         *tls.Certificate
	peer         value.KeyPeer
	busy, closed bool
	lastAttempt  time.Time
	cancel       context.CancelFunc
}

// Server and issuer trust pools are separate and cloned. There is no system-CA,
// insecure-TLS, proxy, cookie, redirect, filesystem-key or provider fallback.
func NewWorkerCredentials(endpoint string, target value.WorkerCredentialTarget, serverRoots, issuerRoots *x509.CertPool, tokens evidence.DownloadPeerToken, now func() time.Time) (*WorkerCredentials, error) {
	return NewWorkerCredentialsVia(endpoint, "", target, serverRoots, issuerRoots, tokens, now)
}

// NewWorkerCredentialsVia is NewWorkerCredentials with the control document's
// optional connectivity-only address: TCP goes to address while TLS still
// verifies endpoint's host and the request names endpoint's authority. An
// empty address is NewWorkerCredentials.
func NewWorkerCredentialsVia(endpoint, address string, target value.WorkerCredentialTarget, serverRoots, issuerRoots *x509.CertPool, tokens evidence.DownloadPeerToken, now func() time.Time) (*WorkerCredentials, error) {
	u, err := workerEndpoint(endpoint)
	if err != nil || workerAddress(address) != nil || !target.Valid() || serverRoots == nil || len(serverRoots.Subjects()) == 0 || tokens == nil || now == nil {
		return nil, artifact.ErrInvalid
	}
	if _, _, err = target.CertificateEpoch(now()); err != nil {
		return nil, err
	}
	verifier, err := NewKeyPeerVerifier(issuerRoots, target.InstallationID, now)
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	if _, err = EnrollmentKey(csr); err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	dial := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	if via := workerDial(u, address, dial); via != nil {
		dial = via
	}
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: serverRoots.Clone(), MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Time: now},
		DialContext:         dial,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1,
		MaxResponseHeaderBytes: 4096, DisableCompression: true,
		// Enrollment is infrequent. A fresh handshake on each attempt validates
		// current server-certificate lifetime before sending the projected token.
		DisableKeepAlives: true,
	}
	u.Path = contracts.WorkerEnrollmentPath
	client := &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &WorkerCredentials{target: target, now: now, tokens: tokens, verifier: verifier, client: client, endpoint: u.String(), key: key, csr: csr}, nil
}

// Enroll retrieves or renews an activated certificate. There is no hidden retry
// loop; one request may be active and failures wait at least one second before
// another caller attempt. SQL independently owns immutable signing budgets.
func (w *WorkerCredentials) Enroll(ctx context.Context) error {
	if w == nil || w.now == nil || w.client == nil || w.tokens == nil || ctx == nil || ctx.Err() != nil {
		return artifact.ErrInvalid
	}
	w.mu.Lock()
	start := w.now()
	_, until, err := w.target.CertificateEpoch(start)
	if err != nil || w.closed || w.busy {
		w.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	if w.peer.Valid(start) && w.peer.NotAfter.Equal(until) {
		w.mu.Unlock()
		return nil
	}
	if !w.lastAttempt.IsZero() && start.Before(w.lastAttempt.Add(time.Second)) {
		w.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	deadline := start.Add(30 * time.Second)
	if w.target.RunUntil.Before(deadline) {
		deadline = w.target.RunUntil
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	w.busy, w.lastAttempt, w.cancel = true, start, cancel
	csr := bytes.Clone(w.csr)
	w.mu.Unlock()
	defer func() { cancel(); w.mu.Lock(); w.busy, w.cancel = false, nil; w.mu.Unlock() }()
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return artifact.ErrDownloadUnavailable
	}
	token, err := w.tokens.ReadDownloadPeerToken(ctx)
	defer clear(token)
	if err != nil || !contracts.ValidWorkerToken(token) {
		return artifact.ErrDownloadUnavailable
	}
	in := contracts.WorkerEnrollmentRequest{Format: contracts.WorkerEnrollmentFormat, InstallationID: w.target.InstallationID, SessionID: w.target.SessionID, QueryID: w.target.QueryID, WorkerID: w.target.WorkerID, Nonce: base64.RawURLEncoding.EncodeToString(nonce[:]), CSR: csr}
	b, err := json.Marshal(in)
	if err != nil || len(b) > contracts.WorkerEnrollmentMaxRequest {
		return artifact.ErrInvalid
	}
	// A non-replayable body prevents transport retry after an uncertain POST.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.endpoint, io.NopCloser(bytes.NewReader(b)))
	if err != nil {
		return artifact.ErrInvalid
	}
	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(token))
	response, err := w.client.Do(req)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Content-Encoding")) != 0 || response.ContentLength > contracts.WorkerEnrollmentMaxResponse || len(response.Trailer) != 0 {
		return artifact.ErrDownloadUnavailable
	}
	out, err := contracts.DecodeWorkerEnrollmentResponse(response.Body)
	if err != nil || out.Format != in.Format || out.InstallationID != in.InstallationID || out.SessionID != in.SessionID || out.QueryID != in.QueryID || out.WorkerID != in.WorkerID || out.Nonce != in.Nonce || out.Chain == nil {
		return artifact.ErrIntegrity
	}
	cert, peer, err := w.checkCertificate(start, csr, out.Certificate, out.Chain)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || ctx.Err() != nil || !w.now().Before(deadline) || !peer.Valid(w.now()) || !w.now().Before(w.target.RunUntil) {
		return artifact.ErrDownloadExpired
	}
	cert.PrivateKey = &workerCredentialSigner{owner: w, peer: peer, public: cert.Leaf.PublicKey}
	w.cert, w.peer = cert, peer
	return nil
}

func (w *WorkerCredentials) checkCertificate(start time.Time, csr, der []byte, chain [][]byte) (*tls.Certificate, value.KeyPeer, error) {
	return checkWorkerCertificate(w.verifier, w.target, w.now, start, csr, der, chain)
}

func checkWorkerCertificate(verifier *KeyPeerVerifier, target value.WorkerCredentialTarget, now func() time.Time, start time.Time, csr, der []byte, chain [][]byte) (*tls.Certificate, value.KeyPeer, error) {
	var zero value.KeyPeer
	if len(der) < 1 || len(der) > 16<<10 || len(chain) > 3 {
		return nil, zero, artifact.ErrIntegrity
	}
	key, err := EnrollmentKey(csr)
	if err != nil {
		return nil, zero, artifact.ErrIntegrity
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != key {
		return nil, zero, artifact.ErrIntegrity
	}
	certs := []*x509.Certificate{leaf}
	raw := [][]byte{bytes.Clone(der)}
	total := len(der)
	for _, der := range chain {
		if len(der) < 1 || len(der) > 16<<10 {
			return nil, zero, artifact.ErrIntegrity
		}
		total += len(der)
		if total > 32<<10 {
			return nil, zero, artifact.ErrIntegrity
		}
		c, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, zero, artifact.ErrIntegrity
		}
		certs = append(certs, c)
		raw = append(raw, bytes.Clone(der))
	}
	peer, err := verifier.verifyCertificates(certs)
	if err != nil || peer.Role != "acquisition" || peer.PeerID != target.PodUID || !peer.NotAfter.Equal(leaf.NotAfter) || peer.NotBefore.Before(target.CreatedAt.Add(-time.Minute)) || leaf.NotAfter.Sub(leaf.NotBefore) > value.WorkerCertificatePeriod+value.WorkerCertificateRenewBefore+time.Minute {
		return nil, zero, artifact.ErrIntegrity
	}
	// A request may straddle the one-minute renewal boundary. Both permitted
	// periods derive from the original worker start, never response timestamps.
	_, first, e1 := target.CertificateEpoch(start)
	_, last, e2 := target.CertificateEpoch(now())
	if e1 != nil || e2 != nil || now().Before(start) || !(peer.NotAfter.Equal(first) || peer.NotAfter.Equal(last)) {
		return nil, zero, artifact.ErrIntegrity
	}
	return &tls.Certificate{Certificate: raw, Leaf: leaf}, peer, nil
}

// GetClientCertificate implements tls.Config's callback. Snapshots already
// returned during renewal remain usable only through their own original expiry.
func (w *WorkerCredentials) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if w == nil || w.now == nil || info == nil || info.Version != tls.VersionTLS13 {
		return nil, artifact.ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.cert == nil || !w.peer.Valid(w.now()) || !w.now().Before(w.target.RunUntil) {
		return nil, artifact.ErrDownloadExpired
	}
	out := *w.cert
	out.Certificate = make([][]byte, len(w.cert.Certificate))
	for i, der := range w.cert.Certificate {
		out.Certificate[i] = bytes.Clone(der)
	}
	// Reparse so callers cannot mutate the installed leaf through a snapshot.
	out.Leaf, _ = x509.ParseCertificate(out.Certificate[0])
	if info.SupportsCertificate(&out) != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	return &out, nil
}

func (w *WorkerCredentials) Peer() (value.KeyPeer, error) {
	if w == nil || w.now == nil {
		return value.KeyPeer{}, artifact.ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.peer.Valid(w.now()) || !w.now().Before(w.target.RunUntil) {
		return value.KeyPeer{}, artifact.ErrDownloadExpired
	}
	return w.peer, nil
}

// PublicKeyDigest identifies this process's original CSR key. It is not a
// certificate, enrollment proof or effect grant and exposes no signing handle.
func (w *WorkerCredentials) PublicKeyDigest() (artifact.Digest, error) {
	if w == nil || w.now == nil {
		return artifact.Digest{}, artifact.ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || !w.now().Before(w.target.RunUntil) {
		return artifact.Digest{}, artifact.ErrDownloadExpired
	}
	return EnrollmentKey(w.csr)
}

// Close cancels enrollment and disables all retained signer snapshots. Go does
// not guarantee heap zeroization; no private key is serialized or written out.
func (w *WorkerCredentials) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.closed = true
	if w.cancel != nil {
		w.cancel()
	}
	w.key, w.cert = nil, nil
	w.peer = value.KeyPeer{}
	w.mu.Unlock()
	if w.client != nil {
		w.client.CloseIdleConnections()
	}
}

type workerCredentialSigner struct {
	owner  *WorkerCredentials
	peer   value.KeyPeer
	public crypto.PublicKey
}

func (s *workerCredentialSigner) Public() crypto.PublicKey { return s.public }
func (s *workerCredentialSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	w := s.owner
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.key == nil || !s.peer.Valid(w.now()) || !w.now().Before(w.target.RunUntil) || opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, artifact.ErrDownloadExpired
	}
	return w.key.Sign(random, digest, opts)
}
