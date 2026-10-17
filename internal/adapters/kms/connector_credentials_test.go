package kms

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnectorCredentialIssuerPinsProviderPurposeBeforeRequest(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, usage := range []string{"client", "server"} {
		t.Run(usage, func(t *testing.T) {
			n := time.Now().UTC().Truncate(time.Second)
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(time.Hour)}
			der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
			if e != nil {
				t.Fatal(e)
			}
			csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			digest, _ := mtls.EnrollmentKey(csr)
			binding := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
			uri, _ := mtls.PeerURI(binding)
			profile := value.ConnectorCredentialProfile{Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}, RootID: id, Binding: binding, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{1}, ServerName: "connector.example.invalid", ClientIssuerRoots: [][]byte{der}, ServerIssuerRoots: [][]byte{der}}
			claimed := n
			if usage == "client" {
				claimed = n.Add(-29 * time.Minute)
			}
			process := value.ConnectorCredentialProcess{BootstrapID: id, Binding: binding, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: claimed, InitialCertificateNotAfter: claimed.Add(30 * time.Minute)}
			if usage == "client" {
				process.ClientKeyDigest = digest
			} else {
				process.ServerKeyDigest = digest
			}
			epoch, end, _ := process.Window(n)
			p := value.ConnectorCredentialPermit{ID: id, Process: process, Usage: usage, Configuration: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: profile, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, CurrentPeer: value.AuthenticatedPeer{Certificate: value.PeerCertificate{Binding: binding, Digest: artifact.Digest{5}, NotBefore: claimed, NotAfter: process.InitialCertificateNotAfter}, RegistrationRevision: profile.Revision, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: profile.Revision, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, IntentDigest: artifact.Digest{6}, Epoch: epoch, Ordinal: 1, CheckedAt: n, SignBefore: n.Add(5 * time.Second), CertificateNotAfter: end}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var wire map[string]any
				if r.Method != "POST" || r.URL.Path != "/v1/connector-pki/sign/"+usage || r.Header.Get("X-Vault-Token") != "synthetic-role" || json.NewDecoder(r.Body).Decode(&wire) != nil {
					t.Error("wrong provider request")
				}
				uris, ok := wire["uri_sans"].([]any)
				if !ok || len(uris) != 1 || uris[0] != uri.String() {
					t.Error("wrong fixed connector identity")
				}
				if usage == "server" {
					if wire["alt_names"] != profile.ServerName {
						t.Error("wrong server DNS SAN/string type")
					}
				} else if _, ok := wire["alt_names"]; ok {
					t.Error("client requested server SAN")
				}
				if wire["not_after"] != end.Format(time.RFC3339) {
					t.Error("original certificate expiry changed")
				}
				w.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()
			issuer, e := NewConnectorCredentialIssuer(server.URL, "synthetic-role", "connector-pki", usage, usage, profile, server.Client(), time.Now)
			if e != nil {
				t.Fatal(e)
			}
			invalid := p
			invalid.Configuration.Profile = invalid.Configuration.Profile.Clone()
			invalid.Configuration.Profile.Revision.UID = "22222222-2222-4222-8222-222222222222"
			if _, e = issuer.SignConnectorCredential(context.Background(), invalid, csr); e == nil || calls.Load() != 0 {
				t.Fatal("foreign producer reached signing provider", e, calls.Load())
			}
			invalid = p
			invalid.IntentDigest = artifact.Digest{}
			if _, e = issuer.SignConnectorCredential(context.Background(), invalid, csr); e == nil || calls.Load() != 0 {
				t.Fatal("unaudited attempt reached provider")
			}
			if _, e = issuer.SignConnectorCredential(context.Background(), p, csr); e == nil || calls.Load() != 1 {
				t.Fatal("uncertain provider call retried or accepted", e, calls.Load())
			}
		})
	}
}
