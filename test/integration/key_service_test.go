package integration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/keyservice"
)

const keyInstallation = "00000000-0000-4000-8000-000000000091"
const keyAuthority = "00000000-0000-4000-8000-000000000092"

// Deliberately test-only accepted authority. Production must derive these
// original bounds from durable current execution/session/recovery authority.
type fixtureKeyAuthority struct {
	mu      sync.Mutex
	allowed map[artifact.Digest]bool
	calls   int
	block   <-chan struct{}
	entered chan<- struct{}
}

func (f *fixtureKeyAuthority) Resolve(ctx context.Context, p value.KeyPeer, r value.KeyRequestInfo) (value.KeyOperationPermit, error) {
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		case <-ctx.Done():
			return value.KeyOperationPermit{}, app.ErrKeyDenied
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return value.KeyOperationPermit{}, app.ErrKeyDenied
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if !f.allowed[p.Certificate] || r.AuthorityID != keyAuthority || (r.Operation != "sign" && !bytes.Equal(r.Binding, []byte("synthetic exact artifact binding"))) || (r.Operation == "sign" && r.InputDigest != artifact.Digest(sha256.Sum256([]byte("synthetic policy signature input")))) {
		return value.KeyOperationPermit{}, app.ErrKeyDenied
	}
	now := time.Now().UTC()
	return value.KeyOperationPermit{AuthorityID: r.AuthorityID, RecoveryEpoch: "00000000-0000-4000-8000-000000000093", Revision: 1, Certificate: p.Certificate, RequestDigest: r.RequestDigest, ObservedAt: now, ValidUntil: now.Add(4 * time.Second)}, nil
}

type keyTLSFixture struct {
	server      *httptest.Server
	root        *x509.Certificate
	rootKey     ed25519.PrivateKey
	roots       *x509.CertPool
	clients     map[string]*http.Client
	digests     map[string]artifact.Digest
	authority   *fixtureKeyAuthority
	scope       value.KeyScope
	public      ed25519.PublicKey
	connections atomic.Int32
	peerShift   atomic.Int64
	serial      int64
}

func (f *keyTLSFixture) certificate(t *testing.T, role string) tls.Certificate {
	return f.certificateForPeer(t, role, "")
}
func (f *keyTLSFixture) certificateForPeer(t *testing.T, role, peerID string) tls.Certificate {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.serial++
	leaf := &x509.Certificate{SerialNumber: big.NewInt(f.serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(20 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	if role == "server" {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if peerID == "" {
			peerID = fmt.Sprintf("00000000-0000-4000-8000-%012d", f.serial)
		}
		u, _ := url.Parse(fmt.Sprintf("spiffe://asservat.%s/key-client/%s/%s", f.scope.InstallationID, role, peerID))
		leaf.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.root, pub, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newKeyTLSFixture(t *testing.T, purpose string, override func(http.Handler) http.Handler) *keyTLSFixture {
	return newKeyTLSFor(t, keyInstallation, purpose, nil, nil, override)
}
func newKeyTLSFor(t *testing.T, installation, purpose string, authority app.KeyOperationAuthorizer, operationBackend app.KeyOperationBackend, override func(http.Handler) http.Handler) *keyTLSFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &keyTLSFixture{root: root, rootKey: key, roots: x509.NewCertPool(), clients: map[string]*http.Client{}, digests: map[string]artifact.Digest{}, authority: &fixtureKeyAuthority{allowed: map[artifact.Digest]bool{}}, scope: value.KeyScope{InstallationID: installation, Purpose: purpose, KeyID: "fixture"}, serial: 1}
	f.roots.AddCert(root)
	for _, role := range []string{"collector", "publisher", "acquisition", "hub-session", "policy-submitter", "audit-writer", "audit-reader"} {
		cert := f.certificate(t, role)
		f.digests[role] = artifact.Digest(sha256.Sum256(cert.Certificate[0]))
		f.authority.allowed[f.digests[role]] = true
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		f.clients[role] = &http.Client{Transport: transport, Timeout: 5 * time.Second}
		t.Cleanup(transport.CloseIdleConnections)
	}
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	version := 0
	if purpose == "policy-submission" {
		f.public = ed25519.NewKeyFromSeed(material).Public().(ed25519.PublicKey)
		version = 1
	}
	secret, err := json.Marshal(map[string]any{"format": "asservat-local-keys/v1", "installationID": installation, "purpose": purpose, "keyID": "fixture", "activeVersion": 1, "keys": []any{map[string]any{"version": 1, "material": material}}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	backend, err := kms.NewLocalOperations(f.scope, version, f.public, bytes.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	peers, err := mtls.NewKeyPeerVerifier(f.roots, installation, func() time.Time { return time.Now().Add(time.Duration(f.peerShift.Load())) })
	if err != nil {
		t.Fatal(err)
	}
	if authority == nil {
		authority = f.authority
	}
	if operationBackend == nil {
		operationBackend = backend
	}
	if _, ok := operationBackend.(app.KeyConfigurationGuard); !ok {
		operationBackend = fixtureConfiguredKeyBackend{operationBackend}
	}
	handler, err := keyservice.NewHandler([]app.KeyService{{Scope: f.scope, Authority: authority, Backend: operationBackend, Now: time.Now}}, peers, time.Now, 2)
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler = handler
	if override != nil {
		h = override(h)
	}
	f.server = httptest.NewUnstartedServer(h)
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{f.certificate(t, "server")}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: f.roots, MinVersion: tls.VersionTLS13}
	f.server.Config.ReadHeaderTimeout = time.Second
	f.server.Config.ReadTimeout = 5 * time.Second
	f.server.Config.WriteTimeout = 5 * time.Second
	f.server.Config.IdleTimeout = 10 * time.Second
	f.server.Config.MaxHeaderBytes = 4096
	f.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			f.connections.Add(1)
		}
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func TestLocalKeyServiceTLSIsolationAndRevocation(t *testing.T) {
	f := newKeyTLSFixture(t, "artifact", nil)
	ctx := context.Background()
	binding := []byte("synthetic exact artifact binding")
	plain := []byte("synthetic keyset")
	writer, err := kms.NewRemoteSealer(f.server.URL, f.scope, keyAuthority, f.clients["collector"])
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kms.NewRemoteOpener(f.server.URL, f.scope, keyAuthority, f.clients["acquisition"])
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := writer.Seal(ctx, plain, binding)
	if err != nil {
		t.Fatal("remote wrap", err)
	}
	got, err := reader.Open(ctx, sealed, binding)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("remote unwrap", err)
	}
	clear(got)
	for _, role := range []string{"collector", "publisher", "hub-session", "audit-reader", "policy-submitter"} {
		wrong, _ := kms.NewRemoteOpener(f.server.URL, f.scope, keyAuthority, f.clients[role])
		if b, err := wrong.Open(ctx, sealed, binding); err == nil || b != nil {
			t.Fatalf("%s gained raw unwrap", role)
		}
	}
	if b, err := reader.Open(ctx, sealed, []byte("another artifact")); err == nil || b != nil {
		t.Fatal("foreign binding acquired a key")
	}
	wrong, _ := kms.NewRemoteOpener(f.server.URL, f.scope, "00000000-0000-4000-8000-000000000099", f.clients["acquisition"])
	if b, err := wrong.Open(ctx, sealed, binding); err == nil || b != nil {
		t.Fatal("caller UUID invented authority")
	}
	connections := f.connections.Load()
	f.authority.mu.Lock()
	f.authority.allowed[f.digests["acquisition"]] = false
	f.authority.mu.Unlock()
	if b, err := reader.Open(ctx, sealed, binding); err == nil || b != nil {
		t.Fatal("revoked key reader acquired a key")
	}
	if f.connections.Load() != connections {
		t.Fatal("revocation test did not use the established connection")
	}
	t.Log("real TLS wrap/read; exact binding and authority; collector/publisher/hub unwrap denial; current revocation on existing TLS connection")
}

func TestLocalKeyServicePurposeAndSigning(t *testing.T) {
	for _, purpose := range []string{"audit", "browser-credentials", "policy-submission"} {
		t.Run(purpose, func(t *testing.T) {
			f := newKeyTLSFixture(t, purpose, nil)
			ctx := context.Background()
			if purpose == "policy-submission" {
				s, err := kms.NewRemoteSigner(f.server.URL, f.scope, keyAuthority, 1, f.public, f.clients["policy-submitter"])
				if err != nil {
					t.Fatal(err)
				}
				input := []byte("synthetic policy signature input")
				sig, err := s.ForContext(ctx).Sign(nil, input, crypto.Hash(0))
				if err != nil || !ed25519.Verify(f.public, input, sig) {
					t.Fatal("remote signing", err)
				}
				if _, err := s.ForContext(ctx).Sign(nil, []byte("unauthorized policy"), crypto.Hash(0)); err == nil {
					t.Fatal("signing oracle accepted uncovered input")
				}
				otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
				wrong, _ := kms.NewRemoteSigner(f.server.URL, f.scope, keyAuthority, 1, otherPub, f.clients["policy-submitter"])
				if _, err := wrong.ForContext(ctx).Sign(nil, input, crypto.Hash(0)); err == nil {
					t.Fatal("signature did not match public pin")
				}
				return
			}
			writeRole, readRole := "audit-writer", "audit-reader"
			if purpose == "browser-credentials" {
				writeRole, readRole = "hub-session", "hub-session"
			}
			sealer, err := kms.NewRemoteSealer(f.server.URL, f.scope, keyAuthority, f.clients[writeRole])
			if err != nil {
				t.Fatal(err)
			}
			opener, err := kms.NewRemoteOpener(f.server.URL, f.scope, keyAuthority, f.clients[readRole])
			if err != nil {
				t.Fatal(err)
			}
			cipher := kms.BrowserCipher{Sealer: sealer, Opener: opener}
			binding := []byte("synthetic exact artifact binding")
			encoded, err := cipher.Encrypt(ctx, []byte("synthetic session or audit payload"), binding)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := cipher.Decrypt(ctx, encoded, binding)
			if err != nil || string(plain) != "synthetic session or audit payload" {
				t.Fatal("envelope provider composition", err)
			}
			clear(plain)
		})
	}
}

func TestLocalKeyServiceRejectsWireSubstitution(t *testing.T) {
	f := newKeyTLSFixture(t, "artifact", nil)
	wire := contracts.KeyServiceRequest{Format: contracts.KeyServiceFormat, Scope: contracts.KeyScope{InstallationID: keyInstallation, Purpose: "artifact", KeyID: "fixture"}, AuthorityID: keyAuthority, Operation: "wrap", Input: []byte("synthetic"), Binding: []byte("synthetic exact artifact binding")}
	b, _ := json.Marshal(wire)
	for name, body := range map[string]string{
		"unknown":           string(b[:len(b)-1]) + `,"secret":"do-not-echo"}`,
		"alias":             strings.Replace(string(b), `"operation"`, `"Operation"`, 1),
		"duplicate":         string(b[:len(b)-1]) + `,"operation":"wrap"}`,
		"trailing":          string(b) + ` {}`,
		"oversized":         strings.Repeat(" ", contracts.KeyServiceMaxBody) + string(b),
		"null-input":        strings.Replace(string(b), `"input":"c3ludGhldGlj"`, `"input":null`, 1),
		"irrelevant-sealed": string(b[:len(b)-1]) + `,"sealed":{"reference":"","ciphertext":""}}`,
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, f.server.URL+contracts.KeyServicePath, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := f.clients["collector"].Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 400 || len(got) != 0 {
				t.Fatalf("invalid body response %d", resp.StatusCode)
			}
		})
	}
	if f.authority.calls != 0 {
		t.Fatal("malformed input reached authority")
	}
	// A verified server connection without a client credential must fail TLS,
	// even if forwarded headers pretend to identify an authorized collector.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.roots, MinVersion: tls.VersionTLS13}}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodPost, f.server.URL+contracts.KeyServicePath, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Client-Cert", "collector")
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("missing client certificate accepted")
	}
}

func TestLocalKeyClientRejectsMalformedResponses(t *testing.T) {
	for _, mode := range []string{"digest", "expired", "operation", "irrelevant-sealed", "unknown", "duplicate", "oversized", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			f := newKeyTLSFixture(t, "artifact", func(_ http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if mode == "redirect" {
						w.Header().Set("Location", "/redirected")
						w.WriteHeader(307)
						return
					}
					in, err := contracts.DecodeKeyRequest(r.Body)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					req := value.KeyRequest{Scope: value.KeyScope{InstallationID: in.Scope.InstallationID, Purpose: in.Scope.Purpose, KeyID: in.Scope.KeyID}, AuthorityID: in.AuthorityID, Operation: in.Operation, Binding: in.Binding, Sealed: artifact.SealedKey{Reference: in.Sealed.Reference, Ciphertext: in.Sealed.Ciphertext}}
					info, _ := app.DescribeKeyRequest(req)
					response := contracts.KeyServiceResponse{Format: contracts.KeyServiceFormat, Operation: "unwrap", RequestSHA256: hex.EncodeToString(info.RequestDigest[:]), ValidUntil: time.Now().Add(3 * time.Second).UTC().Format(time.RFC3339Nano), Output: []byte("synthetic")}
					switch mode {
					case "digest":
						response.RequestSHA256 = strings.Repeat("0", 64)
					case "expired":
						response.ValidUntil = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
					case "operation":
						response.Operation = "sign"
					case "irrelevant-sealed":
						response.Sealed = &contracts.SealedLocalKey{}
					}
					b, _ := json.Marshal(response)
					if mode == "unknown" {
						b = append(b[:len(b)-1], []byte(`,"debug":"do-not-echo"}`)...)
					}
					if mode == "duplicate" {
						b = append(b[:len(b)-1], []byte(`,"operation":"unwrap"}`)...)
					}
					if mode == "oversized" {
						b = append(b, bytes.Repeat([]byte(" "), contracts.KeyServiceMaxBody)...)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(b)
				})
			})
			reader, err := kms.NewRemoteOpener(f.server.URL, f.scope, keyAuthority, f.clients["acquisition"])
			if err != nil {
				t.Fatal(err)
			}
			sealed := artifact.SealedKey{Reference: "asservat-local-keyset/v1/" + keyInstallation + "/artifact/fixture/1", Ciphertext: "synthetic"}
			if b, err := reader.Open(context.Background(), sealed, []byte("synthetic exact artifact binding")); err == nil || b != nil {
				t.Fatal("malformed response returned a key")
			}
			if calls != 1 {
				t.Fatal("client followed redirect or retried")
			}
		})
	}
}

func TestLocalKeyServiceBoundsAndCurrentTLS(t *testing.T) {
	t.Run("certificate-expiry-on-reused-connection", func(t *testing.T) {
		f := newKeyTLSFixture(t, "artifact", nil)
		writer, err := kms.NewRemoteSealer(f.server.URL, f.scope, keyAuthority, f.clients["collector"])
		if err != nil {
			t.Fatal(err)
		}
		binding := []byte("synthetic exact artifact binding")
		if _, err := writer.Seal(context.Background(), []byte("synthetic"), binding); err != nil {
			t.Fatal(err)
		}
		before := f.connections.Load()
		f.peerShift.Store(int64(30 * time.Minute))
		if _, err := writer.Seal(context.Background(), []byte("synthetic"), binding); err == nil {
			t.Fatal("old handshake extended certificate lifetime")
		}
		if f.connections.Load() != before {
			t.Fatal("certificate expiry did not test reused connection")
		}
	})
	t.Run("no-unbounded-queue", func(t *testing.T) {
		f := newKeyTLSFixture(t, "artifact", nil)
		block := make(chan struct{})
		entered := make(chan struct{}, 2)
		f.authority.block = block
		f.authority.entered = entered
		writer, err := kms.NewRemoteSealer(f.server.URL, f.scope, keyAuthority, f.clients["collector"])
		if err != nil {
			t.Fatal(err)
		}
		results := make(chan error, 2)
		for range 2 {
			go func() {
				_, err := writer.Seal(context.Background(), []byte("synthetic"), []byte("synthetic exact artifact binding"))
				results <- err
			}()
		}
		for range 2 {
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(block)
				t.Fatal("requests did not enter authority")
			}
		}
		wire := contracts.KeyServiceRequest{Format: contracts.KeyServiceFormat, Scope: contracts.KeyScope{InstallationID: keyInstallation, Purpose: "artifact", KeyID: "fixture"}, AuthorityID: keyAuthority, Operation: "wrap", Binding: []byte("synthetic exact artifact binding"), Input: []byte("synthetic")}
		b, _ := json.Marshal(wire)
		req, _ := http.NewRequest(http.MethodPost, f.server.URL+contracts.KeyServicePath, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := f.clients["collector"].Do(req)
		close(block)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 429 {
			t.Fatalf("saturation status %d", resp.StatusCode)
		}
		for range 2 {
			if err := <-results; err != nil {
				t.Fatal("admitted operation failed", err)
			}
		}
		f.authority.mu.Lock()
		calls := f.authority.calls
		f.authority.mu.Unlock()
		if calls != 2 {
			t.Fatal("busy request entered authority")
		}
	})
}

// Existing TLS/authority fixtures do not attest protected configuration.
type fixtureConfiguredKeyBackend struct{ app.KeyOperationBackend }

func (fixtureConfiguredKeyBackend) CurrentKeyConfiguration(ctx context.Context, scope value.KeyScope, epoch string) (time.Time, error) {
	if ctx.Err() != nil || !scope.Valid() || !value.UUID(epoch) {
		return time.Time{}, app.ErrKeyUnavailable
	}
	return time.Now().Add(5 * time.Second), nil
}
