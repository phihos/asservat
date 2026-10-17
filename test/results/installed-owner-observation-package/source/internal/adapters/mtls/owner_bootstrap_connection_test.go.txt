package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerBootstrapConnectionOwnsActualHandshakeAndOriginalCandidates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	binding := ownerBootstrapBinding(ownerTestID)
	common, _ := OwnerBootstrapServerName(pool)
	leaf := ca.leaf(t, now, binding, true, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, common) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	tr := &http.Transport{ForceAttemptHTTP2: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: common, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer tr.CloseIdleConnections()
	response, e := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("https://" + common + "/")
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	v, e := NewOwnerPeerVerifierForPool(ca.roots, pool, func() time.Time { return clock })
	if e != nil {
		t.Fatal(e)
	}
	candidates := value.APIContextOwnerCandidates{Pool: pool, Owners: []value.OwnerBinding{binding}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	c, e := NewOwnerBootstrapConnection(v, response.TLS, candidates)
	if e != nil {
		t.Fatal(e)
	}
	initial, e := c.OwnerCertificate()
	if e != nil || initial.Binding != binding {
		t.Fatal("actual selected identity unavailable", e)
	}
	configuration := ownerBootstrapConfiguration(pool, ca, now)
	if _, e = c.VerifyCurrentOwner(configuration); e != nil {
		t.Fatal(e)
	}
	// Caller mutation cannot replace a member or extend its original interval.
	candidates.Owners[0] = ownerBootstrapBinding(ownerOtherID)
	candidates.ValidUntil = now.Add(time.Hour)
	response.TLS.PeerCertificates[0].DNSNames = []string{"other.invalid"}
	response.TLS.ServerName = "other.invalid"
	if got, e := c.OwnerCertificate(); e != nil || got != initial {
		t.Fatal("caller mutated owned TLS/candidate snapshot", e)
	}
	for _, mode := range []string{"suspended", "profile", "service", "roots"} {
		t.Run(mode, func(t *testing.T) {
			changed := configuration
			changed.Configuration = configuration.Configuration.Clone()
			switch mode {
			case "suspended":
				changed.Configuration.Suspended = true
			case "profile":
				changed.Configuration.Pool.NativeBootstrap = ""
			case "service":
				changed.Configuration.Pool.ServiceUID = ownerOtherID
			case "roots":
				changed.Configuration.IssuerRoots = nil
			}
			if _, e := c.VerifyCurrentOwner(changed); e == nil {
				t.Fatal("changed current authority accepted")
			}
		})
	}
	// Check route separation while the candidate is still current, so expiry
	// cannot be the reason the exact-owner constructor rejects this connection.
	if _, e = NewOwnerServerConnection(v, &c.state, binding); e == nil {
		t.Fatal("common SNI entered exact-request owner path")
	}
	clock = now.Add(5 * time.Second)
	if _, e = c.OwnerCertificate(); e == nil {
		t.Fatal("original candidate deadline renewed")
	}
}
