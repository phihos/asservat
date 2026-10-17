package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

func TestConnectorPKIWithRealOpenBao(t *testing.T) {
	path := os.Getenv("ASSERVAT_FLEET_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	}
	if path == "" {
		t.Skip("run make fleet-integration or context-integration")
	}
	var f fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/peer-pki", map[string]any{"type": "pki"}, 204)
	root := request(t, f.KMS, "synthetic-root", "peer-pki/root/generate/internal", map[string]any{"common_name": "synthetic-peer-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	rootPEM := root["data"].(map[string]any)["certificate"].(string)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		t.Fatal("invalid fixture root")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := value.PeerBinding{InstallationID: uuid.NewString(), ClusterID: uuid.NewString(), IssuerEpoch: uuid.NewString(), PeerID: uuid.NewString(), Role: value.ConnectorPeer}
	u, err := mtls.PeerURI(b)
	if err != nil {
		t.Fatal(err)
	}
	role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allowed_uri_sans": []string{u.String()}, "key_type": "any", "server_flag": false, "client_flag": true, "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h", "ttl": "30m"}
	request(t, f.KMS, "synthetic-root", "peer-pki/roles/connector", role, 200)
	request(t, f.KMS, "synthetic-root", "sys/policies/acl/peer-signer", map[string]any{"policy": `path "peer-pki/sign/connector" { capabilities=["update"] }`}, 204)
	token := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{"peer-signer"}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
	bridge := tlsBridge(t, f.KMS)
	signer, err := kms.NewConnectorIssuer(bridge.URL, token, "peer-pki", "connector", b.InstallationID, b.ClusterID, b.IssuerEpoch, roots, bridge.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := mtls.EnrollmentKey(csr)
	if err != nil {
		t.Fatal(err)
	}
	p := value.CertificateIssuePermit{Enrollment: value.Enrollment{BootstrapID: uuid.NewString(), Binding: b, PublicKeyDigest: key, ClaimedAt: now, NotAfter: now.Add(5 * time.Minute)}, ClaimAuditDigest: artifact.Digest{1}, TrustRevision: identity.Revision{UID: "fixture", Generation: 1, Digest: [32]byte{1}}}
	refresh := func() { p.CheckedAt = time.Now().UTC(); p.ValidUntil = p.CheckedAt.Add(5 * time.Second) }
	refresh()
	issued, err := signer.SignConnector(context.Background(), p, csr)
	if err != nil {
		t.Fatal("bounded CSR signing", err)
	}
	if issued.Certificate.Binding != b || issued.Certificate.Digest != artifact.Digest(sha256.Sum256(issued.DER)) || !issued.Certificate.NotAfter.Equal(p.CertificateNotAfter()) {
		t.Fatal("issued identity or deadline mismatch")
	}
	// The issued certificate completes an actual client-auth TLS handshake.
	verifier, err := mtls.NewPeerVerifier(roots, b.InstallationID, value.ConnectorPeer, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := verifier.Verify(r.TLS)
		if e != nil || peer.Binding != b {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	transport := client.Transport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: append([][]byte{issued.DER}, issued.ChainDER...), PrivateKey: private}}
	client.Transport = transport
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("issued client handshake", e)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("issued peer rejected", response.StatusCode)
	}
	t.Run("same-claim-cannot-extend-certificate", func(t *testing.T) {
		refresh()
		second, e := signer.SignConnector(context.Background(), p, csr)
		if e != nil || !second.Certificate.NotAfter.Equal(issued.Certificate.NotAfter) {
			t.Fatal("retry extended certificate", e)
		}
	})
	t.Run("wrong-key-epoch-or-audit", func(t *testing.T) {
		for _, mode := range []string{"key", "epoch", "audit", "expired"} {
			refresh()
			bad := p
			switch mode {
			case "key":
				bad.Enrollment.PublicKeyDigest = artifact.Digest{2}
			case "epoch":
				bad.Enrollment.Binding.IssuerEpoch = uuid.NewString()
			case "audit":
				bad.ClaimAuditDigest = artifact.Digest{}
			case "expired":
				bad.ValidUntil = bad.CheckedAt
			}
			if _, e := signer.SignConnector(context.Background(), bad, csr); e == nil {
				t.Fatal("invalid permit accepted", mode)
			}
		}
	})
	t.Run("audited-activation-with-SQL-S3-and-current-TLS", func(t *testing.T) {
		testAuditedEnrollmentWithRealProvider(t, f, b, csr, private, signer, roots, issued)
	})
	t.Run("provider-role-and-revocation", func(t *testing.T) {
		request(t, f.KMS, token, "peer-pki/roles/other", role, 403)
		request(t, f.KMS, token, "peer-pki/root/generate/internal", map[string]any{"common_name": "forbidden"}, 403)
		wrongURI := "spiffe://asservat." + b.InstallationID + "/untrusted"
		request(t, f.KMS, token, "peer-pki/sign/connector", map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{wrongURI}, "not_after": p.CertificateNotAfter().Format(time.RFC3339)}, 400)
		request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": token}, 204)
		refresh()
		if _, e := signer.SignConnector(context.Background(), p, csr); e == nil {
			t.Fatal("revoked signer remained usable")
		}
	})
}
