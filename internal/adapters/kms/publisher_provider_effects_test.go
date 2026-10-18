package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// ADR-203 decision 3/4: the publisher's three provider purposes log in
// through Kubernetes auth only under the current proof, keep each credential
// on its own path, seal/open audit keys with borrowed tokens and sign only
// this process's verifier URI, which the in-process credential then verifies.
func TestPublisherProviderEffectsAreProofBoundAndPurposeSeparated(t *testing.T) {
	tlsFixture := newOwnerProviderControlFixture(t)
	installation := "10000000-0000-4000-8000-000000002040"
	provider := tlsFixture.server.URL
	roots := [][]byte{tlsFixture.server.Certificate().Raw}
	namespace := contracts.WorkerObjectReference{Name: "asservat", UID: "10000000-0000-4000-8000-000000002042"}
	in := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000002041", Namespace: namespace,
		AuditKeys: contracts.PublisherTransit{Endpoint: provider, Roots: roots, Mount: "audit", Key: providerconfig.PublisherAuditKey(installation)},
		Verifier:  contracts.PublisherVerifier{Endpoint: provider, Roots: roots, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(installation)}}
	selection := contracts.PublisherProviderAuthentication{AuthMount: "publisher-auth", AuthMountAccessor: "auth_kubernetes_1", Namespace: namespace,
		ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(installation), UID: "10000000-0000-4000-8000-000000002043"}}
	recipe, err := providerconfig.PublisherProviderRecipeFor(in, selection)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = recipe.Profile
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(2040), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	jwt := ownerProviderTestJWT(time.Now().Add(600 * time.Second))
	purpose := map[string]string{}
	for _, role := range recipe.Roles {
		purpose[role.Name] = role.Purpose
	}
	var mu sync.Mutex
	var logins, signs int
	var cipher string
	issue := map[string]time.Time{}
	const entity = "10000000-0000-4000-8000-000000002048"
	meta := func(role string) map[string]string {
		return map[string]string{"role": role, "service_account_name": selection.ServiceAccount.Name, "service_account_uid": selection.ServiceAccount.UID, "service_account_namespace": selection.Namespace.Name, "service_account_secret_name": ""}
	}
	tlsFixture.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		at, token := time.Now(), r.Header.Get("X-Vault-Token")
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/auth/publisher-auth/login":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || purpose[body["role"]] == "" || body["jwt"] != string(jwt) {
				w.WriteHeader(403)
				return
			}
			logins++
			issue[body["role"]] = at.Truncate(time.Second)
			auth := ownerProviderAuthReply{ClientToken: body["role"], Accessor: "accessor-" + body["role"], Policies: []string{body["role"]}, TokenPolicies: []string{body["role"]}, Metadata: meta(body["role"]), Orphan: true, EntityID: entity, LeaseDuration: 300, Renewable: true, Type: "service"}
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Auth: &auth})
		case "GET /v1/auth/token/lookup-self":
			issued, known := issue[token]
			if !known {
				w.WriteHeader(403)
				return
			}
			v := initialTokenLookup{ID: token, Accessor: "accessor-" + token, Policies: []string{token}, Path: "auth/publisher-auth/login", Meta: meta(token), Display: "kubernetes-publisher", Orphan: true, Creation: issued.Unix(), CreationTTL: 300, Expire: issued.Add(300 * time.Second), TTL: int64(issued.Add(300*time.Second).Sub(at) / time.Second), MaxTTL: 900, Entity: entity, Type: "service", Renewable: true, Issued: issued}
			raw, _ := json.Marshal(v)
			_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Data: raw})
		case "POST /v1/auth/token/revoke-self":
			w.WriteHeader(204)
		default:
			want := map[string]string{"audit-wrap": "/v1/audit/encrypt/" + in.AuditKeys.Key, "audit-unwrap": "/v1/audit/decrypt/" + in.AuditKeys.Key, "verifier-sign": "/v1/worker-pki/sign/" + in.Verifier.Role}[purpose[token]]
			if want == "" || r.URL.Path != want {
				t.Error("cross-purpose credential reached the provider", r.URL.Path)
				w.WriteHeader(403)
				return
			}
			var body map[string]json.RawMessage
			_ = json.NewDecoder(r.Body).Decode(&body)
			switch purpose[token] {
			case "audit-wrap":
				_ = json.Unmarshal(body["plaintext"], &cipher)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"ciphertext": "synthetic-ciphertext"}})
			case "audit-unwrap":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"plaintext": cipher}})
			default:
				signs++
				var csrPEM string
				var uris []string
				_ = json.Unmarshal(body["csr"], &csrPEM)
				_ = json.Unmarshal(body["uri_sans"], &uris)
				block, _ := pem.Decode([]byte(csrPEM))
				if block == nil || len(uris) != 1 {
					w.WriteHeader(400)
					return
				}
				csr, err := x509.ParseCertificateRequest(block.Bytes)
				u, _ := url.Parse(uris[0])
				if err != nil || u == nil {
					w.WriteHeader(400)
					return
				}
				leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(signs) + 2050), NotBefore: at.Add(-30 * time.Second), NotAfter: at.Add(mtls.VerifierCertificatePeriod), URIs: []*url.URL{u},
					KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
				der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
				if err != nil {
					w.WriteHeader(500)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "ca_chain": []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}}})
			}
		}
	})
	dir := t.TempDir()
	if err = os.WriteFile(filepath.Join(dir, contracts.PublisherProviderTokenFile), jwt, 0o400); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	var current sync.Mutex
	proofOK := false
	proof := func(context.Context) (time.Time, error) {
		current.Lock()
		defer current.Unlock()
		if !proofOK {
			return time.Time{}, ErrKeyService
		}
		return time.Now().Add(5 * time.Second), nil
	}
	unbound := in
	unbound.ProviderAuthentication.RecipeSHA256 = strings.Repeat("0", 64)
	if _, err = NewInstalledPublisherProviderEffects(context.Background(), unbound, files, proof); err == nil {
		t.Fatal("effects composed from an unbound profile")
	}
	s, err := NewInstalledPublisherProviderEffects(context.Background(), in, files, proof)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.CloseAndJoin(context.Background()) }()
	short, end := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer end()
	if s.Prime(short) == nil || logins != 0 {
		t.Fatal("logged in without a current proof", logins)
	}
	current.Lock()
	proofOK = true
	current.Unlock()
	if err = s.Prime(context.Background()); err != nil || logins != 3 {
		t.Fatal("prime did not fund exactly three purposes", err, logins)
	}
	sealed, err := s.Sealer().Seal(context.Background(), []byte("synthetic-keyset"), []byte("binding"))
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := s.Opener().Open(context.Background(), sealed, []byte("binding")); err != nil || string(opened) != "synthetic-keyset" {
		t.Fatal("audit codec did not roundtrip", err)
	}
	signer := s.VerifierSigner()
	for _, uri := range []string{"spiffe://asservat." + installation + "/key-client/acquisition/10000000-0000-4000-8000-000000002049", "spiffe://asservat.10000000-0000-4000-8000-0000000020ff/key-client/verifier/10000000-0000-4000-8000-000000002049", mtls.VerifierCertificateURI(installation, "not-a-peer")} {
		if _, _, err = signer.SignVerifierCertificate(context.Background(), []byte("csr"), uri); err == nil {
			t.Fatal("signed a URI outside this installation's verifier role", uri)
		}
	}
	if signs != 0 {
		t.Fatal("refused URI reached the provider", signs)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	credentials, err := mtls.NewVerifierCredentials(installation, signer, pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()
	if err = credentials.Renew(context.Background()); err != nil || signs != 1 {
		t.Fatal("verifier certificate not issued", err, signs)
	}
	if peer, err := credentials.Peer(); err != nil || peer.Role != "verifier" {
		t.Fatal("verifier peer", peer, err)
	}
	if _, err = credentials.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}); err != nil {
		t.Fatal(err)
	}
	if err = s.CloseAndJoin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = signer.SignVerifierCertificate(context.Background(), []byte("csr"), mtls.VerifierCertificateURI(installation, "10000000-0000-4000-8000-000000002049")); err == nil {
		t.Fatal("signed after close")
	}
}
