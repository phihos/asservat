package mtls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

const ownerTestID = "11111111-1111-4111-8111-111111111111"
const ownerOtherID = "22222222-2222-4222-8222-222222222222"

type ownerTestCA struct {
	cert  *x509.Certificate
	key   ed25519.PrivateKey
	roots *x509.CertPool
}

func newOwnerTestCA(t *testing.T, now time.Time) ownerTestCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic owner issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return ownerTestCA{cert, key, roots}
}

func (ca ownerTestCA) leaf(t *testing.T, now time.Time, b value.OwnerBinding, server bool, mutate func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	u, err := OwnerURI(b)
	if err != nil {
		t.Fatal(err)
	}
	v := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(20 * time.Minute)}
	if server {
		name, _ := OwnerServerName(b)
		v.DNSNames = []string{name}
		v.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	if mutate != nil {
		mutate(v)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, v, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Both directions use actual TLS certificate verification. Synthetic issuance
// here does not qualify the production owner issuer or its Pod enrollment.
func TestOwnerActualMutualTLS(t *testing.T) {
	for _, side := range []string{"server", "client"} {
		for _, mode := range []string{"valid", "wrong-installation", "wrong-cluster", "wrong-epoch", "wrong-pod", "wrong-process", "extra-uri", "uri-query", "common-name", "extra-dns", "dual-purpose", "wrong-purpose", "overlong", "expired-connection", "wrong-root", "tls12"} {
			t.Run(side+"/"+mode, func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				var clock atomic.Int64
				clock.Store(now.UnixNano())
				readClock := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
				ca := newOwnerTestCA(t, now)
				binding := value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID}
				changed := binding
				switch mode {
				case "wrong-installation":
					changed.InstallationID = ownerOtherID
				case "wrong-cluster":
					changed.ClusterID = ownerOtherID
				case "wrong-epoch":
					changed.IssuerEpoch = ownerOtherID
				case "wrong-pod":
					changed.PodUID = ownerOtherID
				case "wrong-process":
					changed.ProcessEpoch = ownerOtherID
				}
				mutate := func(c *x509.Certificate) {
					switch mode {
					case "extra-uri":
						c.URIs = append(c.URIs, c.URIs[0])
					case "uri-query":
						c.URIs[0].RawQuery = "ignored=true"
					case "common-name":
						c.Subject.CommonName = "owner"
					case "extra-dns":
						c.DNSNames = append(c.DNSNames, "extra.invalid")
					case "dual-purpose":
						c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
					case "wrong-purpose":
						if side == "server" {
							c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
						} else {
							c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
						}
					case "overlong":
						c.NotAfter = now.Add(2 * time.Hour)
					}
				}
				serverCert, clientCert := ca.leaf(t, now, binding, true, nil), ca.leaf(t, now, binding, false, nil)
				if side == "server" {
					serverCert = ca.leaf(t, now, changed, true, mutate)
				} else {
					clientCert = ca.leaf(t, now, changed, false, mutate)
				}
				roots := ca.roots
				if mode == "wrong-root" {
					roots = newOwnerTestCA(t, now).roots
				}
				verifier, err := NewOwnerPeerVerifier(roots, ownerTestID, ownerTestID, ownerTestID, readClock)
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "expired-connection" {
						clock.Store(now.Add(time.Hour).UnixNano())
					}
					cert, err := verifier.VerifyClient(r.TLS)
					// VerifyClient identifies the peer. The receiver must independently
					// match that identity to its current pool/expected request.
					if side == "client" && (err != nil || cert.Binding != binding) {
						w.WriteHeader(403)
						return
					}
					w.WriteHeader(204)
				}))
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, Time: readClock}
				if mode == "tls12" {
					server.TLS.MinVersion, server.TLS.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
				}
				server.StartTLS()
				defer server.Close()
				name, _ := OwnerServerName(binding)
				transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ca.roots, ServerName: name, Certificates: []tls.Certificate{clientCert}, Time: readClock}}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				response, err := client.Get(server.URL)
				accepted := err == nil && response.StatusCode == 204
				if response != nil {
					response.Body.Close()
					if side == "server" {
						cert, err := verifier.VerifyServer(response.TLS, binding)
						accepted = accepted && err == nil && cert.Binding == binding && cert.Valid(readClock())
					}
				}
				if accepted != (mode == "valid") {
					t.Fatalf("accepted=%v err=%v", accepted, err)
				}
			})
		}
	}
}
