package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Actual provider role separation, signing and mutual TLS. Accepted enrollment,
// recovery and signing spend below are explicit fixture inputs, not runtime
// activation or permission to expose this issuer as a public endpoint.
func TestEnrollmentOwnerPKIWithRealServices(t *testing.T) {
	testEnrollmentOwnerPKIWithRealServices(t, false)
}

func TestEnrollmentOwnerBootstrapPKIWithRealServices(t *testing.T) {
	testEnrollmentOwnerPKIWithRealServices(t, true)
}

func testEnrollmentOwnerPKIWithRealServices(t *testing.T, bootstrap bool) {
	t.Helper()
	path := os.Getenv("ASSERVAT_FLEET_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	}
	if path == "" {
		t.Skip("run make fleet-integration or context-integration")
	}
	raw, e := os.ReadFile(path)
	var f fixture
	if e != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	mount := "owner-pki"
	if bootstrap {
		mount = "owner-bootstrap-pki"
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+mount, map[string]any{"type": "pki"}, 204)
	result := request(t, f.KMS, "synthetic-root", mount+"/root/generate/internal", map[string]any{"common_name": "synthetic-owner-root", "ttl": "1h", "key_type": "ec", "key_bits": 256}, 200)
	rootPEM := result["data"].(map[string]any)["certificate"].(string)
	block, _ := pem.Decode([]byte(rootPEM))
	if block == nil {
		t.Fatal("fixture CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		t.Fatal("fixture roots")
	}
	bridge := tlsBridge(t, f.KMS)
	b := value.OwnerBinding{InstallationID: custodyID(), ClusterID: custodyID(), IssuerEpoch: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID()}
	c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: b.InstallationID, ClusterID: b.ClusterID, IssuerEpoch: b.IssuerEpoch, Namespace: "hub", NamespaceUID: custodyID(), Service: "owner", ServiceUID: custodyID(), Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443}, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{block.Bytes}}
	commonName := ""
	if bootstrap {
		c.Pool.NativePort = 9444
		c.Pool.NativeBootstrap = value.OwnerBootstrapProfile
		commonName, e = mtls.OwnerBootstrapServerName(c.Pool)
		if e != nil {
			t.Fatal(e)
		}
	}
	uri, _ := mtls.OwnerURI(b)
	name, _ := mtls.OwnerServerName(b)
	tokens := map[string]string{}
	signers := map[string]*kms.OwnerCertificateIssuer{}
	certs := map[string]value.IssuedOwnerCertificate{}
	private := map[string]ed25519.PrivateKey{}
	csrs := map[string][]byte{}
	permit := func(usage string) value.OwnerCertificatePermit {
		n := time.Now().UTC()
		epoch, until, e := value.OwnerCertificateWindow(n)
		if e != nil {
			t.Fatal(e)
		}
		key, e := mtls.EnrollmentKey(csrs[usage])
		if e != nil {
			t.Fatal(e)
		}
		return value.OwnerCertificatePermit{ID: custodyID(), Binding: b, Usage: usage, PublicKeyDigest: key, EnrollmentAudit: artifact.Digest{3}, Configuration: value.OwnerConfigurationObservation{Configuration: c, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: b.InstallationID, IssuerEpoch: b.IssuerEpoch, Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: [32]byte{4}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: n, SignBefore: n.Add(5 * time.Second), CertificateNotAfter: until}
	}
	for _, usage := range []string{"server", "client"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_uri_sans": []string{uri.String()}, "key_type": "any", "server_flag": usage == "server", "client_flag": usage == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h", "ttl": "20m"}
		if usage == "server" {
			role["allowed_domains"] = []string{name}
			if bootstrap {
				role["allowed_domains"] = []string{name, commonName}
			}
			role["allow_bare_domains"] = true
		}
		request(t, f.KMS, "synthetic-root", mount+"/roles/"+usage, role, 200)
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+mount+"-"+usage, map[string]any{"policy": `path "` + mount + `/sign/` + usage + `" { capabilities=["update"] }`}, 204)
		token := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{mount + "-" + usage}, "no_default_policy": true, "ttl": "15m"}, 200)["auth"].(map[string]any)["client_token"].(string)
		tokens[usage] = token
		signer, e := kms.NewOwnerCertificateIssuer(bridge.URL, token, mount, usage, b.InstallationID, b.ClusterID, b.IssuerEpoch, usage, roots, bridge.Client(), time.Now)
		if bootstrap {
			signer, e = kms.NewOwnerCertificateIssuerForPool(bridge.URL, token, mount, usage, c.Pool, usage, roots, bridge.Client(), time.Now)
		}
		if e != nil {
			t.Fatal(e)
		}
		signers[usage] = signer
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		private[usage] = key
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		csrs[usage] = csr
		p := permit(usage)
		cert, e := signer.SignOwnerCertificate(context.Background(), p, csr)
		if e != nil || !p.Matches(cert) {
			t.Fatal("actual owner CSR signing", usage, e)
		}
		certs[usage] = cert
		// Separate retry requests with the same spent attempt keep the exact
		// requested expiry; production concurrency/spend belongs to SQL.
		again, e := signer.SignOwnerCertificate(context.Background(), p, csr)
		if e != nil || !again.Certificate.NotAfter.Equal(cert.Certificate.NotAfter) {
			t.Fatal("signing changed requested expiry", e)
		}
	}
	v, e := mtls.NewOwnerPeerVerifier(roots, b.InstallationID, b.ClusterID, b.IssuerEpoch, time.Now)
	if bootstrap {
		v, e = mtls.NewOwnerPeerVerifierForPool(roots, c.Pool, time.Now)
	}
	if e != nil {
		t.Fatal(e)
	}
	exerciseOwnerRegistration(t, f, c, b, csrs, signers, v)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, e := v.VerifyClient(r.TLS)
		if e != nil || got.Binding != b {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(204)
	}))
	leaf := certs["server"]
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: append([][]byte{leaf.DER}, leaf.ChainDER...), PrivateKey: private["server"]}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	leaf = certs["client"]
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, Certificates: []tls.Certificate{{Certificate: append([][]byte{leaf.DER}, leaf.ChainDER...), PrivateKey: private["client"]}}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, e := client.Get(server.URL)
	if e != nil {
		t.Fatal("issued mutual TLS", e)
	}
	response.Body.Close()
	got, e := v.VerifyServer(response.TLS, b)
	if response.StatusCode != 204 || e != nil || got.Binding != b {
		t.Fatal("actual issued owner identities rejected", e)
	}
	if bootstrap {
		exactState := response.TLS
		bootstrapTransport := transport.Clone()
		bootstrapTransport.TLSClientConfig.ServerName = commonName
		defer bootstrapTransport.CloseIdleConnections()
		bootstrapClient := &http.Client{Transport: bootstrapTransport, Timeout: 5 * time.Second}
		now := time.Now().UTC()
		candidates := value.APIContextOwnerCandidates{Pool: c.Pool, Owners: []value.OwnerBinding{b}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
		response, e := bootstrapClient.Get(server.URL)
		if e != nil {
			t.Fatal("actual opted bootstrap TLS", e)
		}
		response.Body.Close()
		got, e := v.VerifyBootstrapServer(response.TLS, candidates)
		if response.StatusCode != 204 || response.ProtoMajor != 2 || e != nil || got.Binding != b {
			t.Fatal("actual opted bootstrap candidate verification", e)
		}
		if _, e := v.VerifyServer(response.TLS, b); e == nil {
			t.Fatal("common SNI entered exact-owner verification")
		}
		candidates.Owners[0].ProcessEpoch = custodyID()
		if _, e := v.VerifyBootstrapServer(response.TLS, candidates); e == nil {
			t.Fatal("actual owner absent from independent candidates accepted")
		}
		legacy, e := mtls.NewOwnerPeerVerifier(roots, b.InstallationID, b.ClusterID, b.IssuerEpoch, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := legacy.VerifyServer(exactState, b); e == nil {
			t.Fatal("legacy verifier accepted opted certificate")
		}
		// A provider role cannot accept an unapproved third SAN, even with a
		// valid original key/CSR. These are fixture issuer credentials only.
		request(t, f.KMS, tokens["server"], mount+"/sign/server", map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrs["server"]})), "alt_names": name + "," + commonName + ",unapproved.example", "uri_sans": uri.String(), "ttl": "10m"}, 400)
	}
	for _, mode := range []string{"key", "purpose", "process", "expired", "recovery", "audit", "current-root"} {
		p := permit("client")
		switch mode {
		case "key":
			p.PublicKeyDigest = artifact.Digest{9}
		case "purpose":
			p.Usage = "server"
		case "process":
			p.Binding.ProcessEpoch = custodyID()
		case "expired":
			p.SignBefore = p.CheckedAt
		case "recovery":
			p.Recovery.FreshUntil = p.CheckedAt
		case "audit":
			p.EnrollmentAudit = artifact.Digest{}
		case "current-root":
			p.Configuration.Configuration = c.Clone()
			p.Configuration.Configuration.IssuerRoots = [][]byte{[]byte("invalid root")}
		}
		if _, e = signers["client"].SignOwnerCertificate(context.Background(), p, csrs["client"]); e == nil {
			t.Fatal("invalid owner permit accepted", mode)
		}
	}
	request(t, f.KMS, tokens["client"], mount+"/sign/server", map[string]any{}, 403)
	request(t, f.KMS, tokens["server"], mount+"/roles/server", map[string]any{"allow_any_name": true}, 403)
	request(t, f.KMS, tokens["server"], mount+"/root/generate/internal", map[string]any{"common_name": "forbidden"}, 403)
	request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": tokens["client"]}, 204)
	if _, e = signers["client"].SignOwnerCertificate(context.Background(), permit("client"), csrs["client"]); e == nil {
		t.Fatal("revoked issuer accepted")
	}
	t.Log("OpenBao server/client CSR signing, exact URI/DNS/usage/deadline, real mutual TLS, distinct provider roles and revoked credential denial; direct issuer permits are synthetic; separate composed registration lifecycle exercised above; no protected bootstrap or forwarding")
}
