package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// The actual selected server is the seventeenth original process in one Pod.
// The complete input is synthetic here; SQL completeness has its own native
// fixture. No process is inferred from an epoch sort order or a Pod alone.
func TestOwnerObservationBootstrapUsesCompleteOptedCandidateBound(t *testing.T) {
	now := time.Now().UTC()
	ca := newOwnerTestCA(t, now)
	pool := ownerBootstrapPool()
	pool.NativeCandidateLimit = 17
	candidates := value.APIContextOwnerCandidates{Pool: pool, ObservedAt: now, ValidUntil: now.Add(4 * time.Second)}
	for i := 1; i <= 17; i++ {
		b := ownerBootstrapBinding(ownerTestID)
		b.ProcessEpoch = fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		candidates.Owners = append(candidates.Owners, b)
	}
	served := candidates.Owners[16]
	common, _ := OwnerBootstrapServerName(pool)
	leaf := ca.leaf(t, now, served, true, func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, common) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: common, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+common+"/", nil)
	if e != nil {
		t.Fatal(e)
	}
	res, e := (&http.Client{Transport: transport}).Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	verifier, e := NewOwnerPeerVerifierForPool(ca.roots, pool, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	got, e := verifier.VerifyBootstrapServer(res.TLS, candidates)
	if e != nil || got.Binding != served {
		t.Fatal("original seventeenth process excluded", e)
	}
	shortened := candidates
	shortened.Owners = append([]value.OwnerBinding(nil), candidates.Owners[:16]...)
	if _, e = verifier.VerifyBootstrapServer(res.TLS, shortened); e == nil {
		t.Fatal("same Pod substituted an absent process")
	}
	for _, limit := range []int{0, 16} {
		p := pool
		p.NativeCandidateLimit = limit
		v, e := NewOwnerPeerVerifierForPool(ca.roots, p, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		changed := candidates
		changed.Pool = p
		if _, e = v.VerifyBootstrapServer(res.TLS, changed); e == nil {
			t.Fatal("unconfigured complete population accepted", limit)
		}
	}
}
