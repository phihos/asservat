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

func TestPeerCertificateActualTLS(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"connector", "node", "wrong-installation", "wrong-role", "two-identities", "dns-identity", "common-name", "server-purpose", "dual-purpose", "overlong", "expired-connection", "wrong-root", "no-client-cert", "tls12"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			var clock atomic.Int64
			clock.Store(now.UnixNano())
			readClock := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			ca, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			p := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
			role := value.ConnectorPeer
			if mode == "node" {
				role = value.NodePeer
				p.Role = role
				p.NodeUID = id
				p.NodeBootID = id
				p.CollectorEpoch = id
			}
			if mode == "wrong-installation" {
				p.InstallationID = "22222222-2222-4222-8222-222222222222"
			}
			u, err := PeerURI(p)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{u}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(30 * time.Minute)}
			switch mode {
			case "wrong-role":
				role = value.NodePeer
			case "two-identities":
				leaf.URIs = append(leaf.URIs, u)
			case "dns-identity":
				leaf.DNSNames = []string{"node.example.invalid"}
			case "common-name":
				leaf.Subject.CommonName = "node"
			case "server-purpose":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "dual-purpose":
				leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
			case "overlong":
				leaf.NotAfter = now.Add(2 * time.Hour)
			}
			clientPub, clientKey, _ := ed25519.GenerateKey(rand.Reader)
			clientDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, clientPub, key)
			if err != nil {
				t.Fatal(err)
			}
			verifyRoots := roots
			if mode == "wrong-root" {
				otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
				otherDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, otherPub, otherKey)
				if e != nil {
					t.Fatal(e)
				}
				other, e := x509.ParseCertificate(otherDER)
				if e != nil {
					t.Fatal(e)
				}
				verifyRoots = x509.NewCertPool()
				verifyRoots.AddCert(other)
			}
			v, err := NewPeerVerifier(verifyRoots, id, role, readClock)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "expired-connection" {
					clock.Store(now.Add(time.Hour).UnixNano())
				}
				got, e := v.Verify(r.TLS)
				if e != nil {
					w.WriteHeader(403)
					return
				}
				if got.Binding != p {
					t.Error("wrong peer")
				}
				w.WriteHeader(204)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, Time: readClock}
			if mode == "tls12" {
				server.TLS.MinVersion = tls.VersionTLS12
				server.TLS.MaxVersion = tls.VersionTLS12
			}
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			transport := client.Transport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{clientDER}, PrivateKey: clientKey}}
			if mode == "no-client-cert" {
				transport.TLSClientConfig.Certificates = nil
			}
			client.Transport = transport
			client.Timeout = 3 * time.Second
			response, e := client.Get(server.URL)
			success := e == nil && response.StatusCode == 204
			if response != nil {
				response.Body.Close()
			}
			if success != (mode == "connector" || mode == "node") {
				t.Fatalf("mode %s accepted=%v err=%v", mode, success, e)
			}
		})
	}
}

func TestPeerURIRejectsAliases(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	p := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	u, _ := PeerURI(p)
	for _, suffix := range []string{"/", "?", "?query=value", "#fragment", "/.."} {
		v, _ := url.Parse(u.String() + suffix)
		if _, err := parsePeerURI(v, id, p.Role); err == nil {
			t.Fatal("alias accepted", suffix)
		}
	}
	if _, err := (&PeerVerifier{}).Verify(nil); err == nil {
		t.Fatal("nil TLS accepted")
	}
}
