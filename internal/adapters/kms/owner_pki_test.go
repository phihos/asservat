package kms

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOwnerIssuerWireTypesPurposeAndNoAutomaticRetry(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, usage := range []string{"server", "client"} {
		t.Run(usage, func(t *testing.T) {
			b := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
			uri, _ := mtls.OwnerURI(b)
			name, _ := mtls.OwnerServerName(b)
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var wire map[string]any
				if r.Method != "POST" || r.URL.Path != "/v1/owner-pki/sign/"+usage || r.Header.Get("X-Vault-Token") != "synthetic-role" || json.NewDecoder(r.Body).Decode(&wire) != nil {
					t.Error("wrong provider request")
				}
				if usage == "server" {
					if wire["alt_names"] != name {
						t.Error("OpenBao requires a string DNS SAN")
					}
				} else {
					if _, present := wire["alt_names"]; present {
						t.Error("client requested DNS SAN")
					}
				}
				uris, ok := wire["uri_sans"].([]any)
				if !ok || len(uris) != 1 || uris[0] != uri.String() {
					t.Error("wrong URI identity")
				}
				if wire["exclude_cn_from_sans"] != true || wire["format"] != "pem" {
					t.Error("wrong certificate format")
				}
				w.WriteHeader(429)
				_, _ = w.Write([]byte(`{"errors":["synthetic provider detail"]}`))
			}))
			defer server.Close()
			// This fixture rejects the POST; issuer-result trust is independently
			// exercised with actual CA certificates in unit/provider tests.
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			_, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
			if e != nil {
				t.Fatal(e)
			}
			key, e := mtls.EnrollmentKey(csr)
			if e != nil {
				t.Fatal(e)
			}
			n := time.Now().UTC()
			epoch, until, _ := value.OwnerCertificateWindow(n)
			c := value.OwnerConfiguration{Pool: value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{server.Certificate().Raw}}
			p := value.OwnerCertificatePermit{ID: id, Binding: b, Usage: usage, PublicKeyDigest: key, EnrollmentAudit: artifact.Digest{3}, Configuration: value.OwnerConfigurationObservation{Configuration: c, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{4}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: n, SignBefore: n.Add(5 * time.Second), CertificateNotAfter: until}
			s, e := NewOwnerCertificateIssuer(server.URL, "synthetic-role", "owner-pki", usage, id, id, id, usage, roots, server.Client(), time.Now)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.SignOwnerCertificate(context.Background(), p, csr); !errors.Is(e, ErrKeyService) || calls != 1 {
				t.Fatal("provider failure retried or leaked", e, calls)
			}
			p.EnrollmentAudit = artifact.Digest{}
			if _, e = s.SignOwnerCertificate(context.Background(), p, csr); e == nil || calls != 1 {
				t.Fatal("unacknowledged permit reached provider")
			}
		})
	}
}
