package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerBootstrapPool() value.OwnerPool {
	return value.OwnerPool{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, Namespace: "hub", NamespaceUID: ownerTestID, Service: "owners", ServiceUID: ownerTestID, Deployment: "hub", DeploymentUID: ownerTestID, ServiceAccount: "hub", AccountUID: ownerTestID, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
}
func ownerBootstrapBinding(pod string) value.OwnerBinding {
	return value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: pod, ProcessEpoch: pod}
}
func ownerBootstrapConfiguration(pool value.OwnerPool, ca ownerTestCA, now time.Time) value.OwnerConfigurationObservation {
	return value.OwnerConfigurationObservation{Configuration: value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: ownerTestID, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{ca.cert.Raw}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}

func TestOwnerBootstrapStrictProfileAndLegacyOmission(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	exactBinding := ownerBootstrapBinding(ownerTestID)
	common, e := OwnerBootstrapServerName(pool)
	if e != nil {
		t.Fatal(e)
	}
	opted, e := NewOwnerPeerVerifierForPool(ca.roots, pool, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	legacy, e := NewOwnerPeerVerifier(ca.roots, pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"opted", "legacy", "missing-exact", "duplicate-common", "extra", "wrong-service", "client", "client-with-dns"} {
		t.Run(mode, func(t *testing.T) {
			server := mode != "client" && mode != "client-with-dns"
			leaf := ca.leaf(t, now, exactBinding, server, func(c *x509.Certificate) {
				if server && mode != "legacy" {
					c.DNSNames = append(c.DNSNames, common)
				}
				switch mode {
				case "missing-exact":
					c.DNSNames = []string{common}
				case "duplicate-common":
					c.DNSNames = []string{common, common}
				case "extra":
					c.DNSNames = append(c.DNSNames, "extra.invalid")
				case "wrong-service":
					c.DNSNames[1] = strings.Replace(common, ownerTestID, ownerOtherID, 1)
				case "client-with-dns":
					c.DNSNames = []string{common}
				}
			})
			parsed, e := x509.ParseCertificate(leaf.Certificate[0])
			if e != nil {
				t.Fatal(e)
			}
			usage := "server"
			if !server {
				usage = "client"
			}
			_, oe := opted.verifyCertificates([]*x509.Certificate{parsed}, usage)
			_, le := legacy.verifyCertificates([]*x509.Certificate{parsed}, usage)
			if (oe == nil) != (mode == "opted" || mode == "client") || (le == nil) != (mode == "legacy" || mode == "client") {
				t.Fatalf("profile outcome opted=%v legacy=%v", oe, le)
			}
		})
	}
	config := ownerBootstrapConfiguration(pool, ca, now)
	if _, e = opted.currentVerifier(config); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"removed", "service", "unknown", "current-roots"} {
		t.Run("current-"+mode, func(t *testing.T) {
			changed := config
			changed.Configuration = changed.Configuration.Clone()
			switch mode {
			case "removed":
				changed.Configuration.Pool.NativeBootstrap = ""
			case "service":
				changed.Configuration.Pool.ServiceUID = ownerOtherID
			case "unknown":
				changed.Configuration.Pool.NativeBootstrap = "other"
			case "current-roots":
				changed.Configuration.IssuerRoots = nil
			}
			if _, e := opted.currentVerifier(changed); e == nil {
				t.Fatal("changed accepted profile survived")
			}
		})
	}
	if _, e = legacy.currentVerifier(config); e == nil {
		t.Fatal("legacy constructor inferred opted profile")
	}
	old := pool
	old.NativeBootstrap = ""
	data, e := json.Marshal(old)
	if e != nil || strings.Contains(string(data), "NativeBootstrap") {
		t.Fatal("legacy omitted bytes changed", e)
	}
	if _, e = OwnerBootstrapServerName(old); e == nil {
		t.Fatal("unopted pool got common name")
	}
	old.NativeBootstrap = value.OwnerBootstrapProfile
	old.NativePort = 0
	if old.Valid() {
		t.Fatal("bootstrap profile without native port")
	}
}

// Actual TLS13/h2 matches the second synthetic candidate at one test endpoint.
// Candidate/registration state here is synthetic; this tests cryptographic
// bootstrap selection, not SQL activation or native multi-cluster reachability.
func TestOwnerBootstrapActualTLSCandidateSetAndExactRoutes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	first, served := ownerBootstrapBinding(ownerTestID), ownerBootstrapBinding(ownerOtherID)
	common, _ := OwnerBootstrapServerName(pool)
	exact, _ := OwnerServerName(served)
	verifier, e := NewOwnerPeerVerifierForPool(ca.roots, pool, func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	serverLeaf := ca.leaf(t, now, served, true, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, common) })
	clientLeaf := ca.leaf(t, now, first, false, nil)
	parsed, e := x509.ParseCertificate(serverLeaf.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	serverLeaf.Leaf = parsed
	cert, e := verifier.verifyCertificates([]*x509.Certificate{parsed}, "server")
	if e != nil {
		t.Fatal(e)
	}
	// Only the serving key fixture is synthetic. The wrapper and TLS hostname,
	// roots, protocol negotiation and peer chain are the production mechanisms.
	credentials := &OwnerCredentials{binding: served, usage: "server", verifier: verifier, now: func() time.Time { return now }, cert: &serverLeaf, identity: cert}
	wrapped, e := NewOwnerBootstrapServing(credentials, pool)
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{common, exact} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			srv.EnableHTTP2 = true
			srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots, GetCertificate: wrapped.GetCertificate, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
			srv.StartTLS()
			defer srv.Close()
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: name, MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{clientLeaf}}, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
			}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
			response, e := client.Get("https://" + name + "/")
			if e != nil {
				t.Fatal("ordinary pinned TLS hostname", e)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.TLS == nil || response.ProtoMajor != 2 {
				t.Fatal("actual h2 handshake missing")
			}
			candidates := value.APIContextOwnerCandidates{Pool: pool, Owners: []value.OwnerBinding{first, served}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			if name == common {
				got, e := verifier.VerifyBootstrapServer(response.TLS, candidates)
				if e != nil || got.Binding != served {
					t.Fatal("second candidate denied", e)
				}
				if _, e = verifier.VerifyServer(response.TLS, served); e == nil {
					t.Fatal("common SNI accepted as exact-owner connection")
				}
				candidates.Owners = []value.OwnerBinding{first}
				if _, e = verifier.VerifyBootstrapServer(response.TLS, candidates); e == nil {
					t.Fatal("leaf added an unlisted owner")
				}
				candidates.Owners = []value.OwnerBinding{served}
				candidates.ValidUntil = now
				if _, e = verifier.VerifyBootstrapServer(response.TLS, candidates); e == nil {
					t.Fatal("expired original candidates renewed")
				}
			} else {
				if _, e = verifier.VerifyServer(response.TLS, served); e != nil {
					t.Fatal("opted exact-server leaf denied", e)
				}
				connection, e := NewOwnerServerConnection(verifier, response.TLS, served)
				if e != nil {
					t.Fatal("exact connection", e)
				}
				current := ownerBootstrapConfiguration(pool, ca, now)
				if _, e = connection.VerifyCurrentOwner(current); e != nil {
					t.Fatal("current connection dropped opted profile", e)
				}
				current.Configuration.Pool.NativeBootstrap = ""
				if _, e = connection.VerifyCurrentOwner(current); e == nil {
					t.Fatal("current connection retained removed capability")
				}

				if _, e = verifier.VerifyServer(response.TLS, first); e == nil {
					t.Fatal("common SAN redirected exact owner")
				}
				if _, e = verifier.VerifyBootstrapServer(response.TLS, candidates); e == nil {
					t.Fatal("exact SNI misclassified as bootstrap")
				}
			}
		})
	}
	// Ordinary credentials never open the common name on other listeners.
	if _, e = credentials.GetCertificate(&tls.ClientHelloInfo{ServerName: common, SupportedVersions: []uint16{tls.VersionTLS13}}); e == nil {
		t.Fatal("ordinary serving credential widened common SNI")
	}
}
