package mtls

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOwnerConnectionSnapshotsActualTLSAndRevalidatesCurrentRoots(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	ca := newOwnerTestCA(t, now)
	binding := value.OwnerBinding{InstallationID: ownerTestID, ClusterID: ownerTestID, IssuerEpoch: ownerTestID, PodUID: ownerTestID, ProcessEpoch: ownerTestID}
	verifier, e := NewOwnerPeerVerifier(ca.roots, ownerTestID, ownerTestID, ownerTestID, func() time.Time { return clock })
	if e != nil {
		t.Fatal(e)
	}
	serverCertificate := ca.leaf(t, now, binding, true, nil)
	clientCertificate := ca.leaf(t, now, binding, false, nil)
	snapshots := make(chan *OwnerConnection, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, e := NewOwnerClientConnection(verifier, r.TLS)
		if e != nil {
			w.WriteHeader(403)
			return
		}
		snapshots <- peer
		w.WriteHeader(204)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.roots}
	server.StartTLS()
	defer server.Close()
	name, _ := OwnerServerName(binding)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.roots, ServerName: name, Certificates: []tls.Certificate{clientCertificate}}}
	defer transport.CloseIdleConnections()
	response, e := (&http.Client{Transport: transport, Timeout: time.Second}).Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal("actual client TLS rejected")
	}
	serverPeer, e := NewOwnerServerConnection(verifier, response.TLS, binding)
	if e != nil {
		t.Fatal(e)
	}
	var clientPeer *OwnerConnection
	select {
	case clientPeer = <-snapshots:
	case <-time.After(time.Second):
		t.Fatal("missing client TLS snapshot")
	}
	wrong := binding
	wrong.ProcessEpoch = ownerOtherID
	if _, e = NewOwnerServerConnection(verifier, response.TLS, wrong); e == nil {
		t.Fatal("expected owner binding ignored")
	}
	partial := *response.TLS
	partial.HandshakeComplete = false
	if _, e = NewOwnerServerConnection(verifier, &partial, binding); e == nil {
		t.Fatal("uncompleted handshake accepted")
	}
	partial = *response.TLS
	partial.VerifiedChains = nil
	if _, e = NewOwnerServerConnection(verifier, &partial, binding); e == nil {
		t.Fatal("unverified handshake accepted")
	}
	for _, peer := range []*OwnerConnection{serverPeer, clientPeer} {
		cert, e := peer.OwnerCertificate()
		if e != nil {
			t.Fatal(e)
		}
		config := ownerPermit(now, [][]byte{ca.cert.Raw}, cert.Digest, cert.Usage).Configuration
		if checked, e := peer.VerifyCurrentOwner(config); e != nil || checked != cert {
			t.Fatal("current verified peer", e)
		}
		changed := config
		changed.Configuration = changed.Configuration.Clone()
		changed.Configuration.IssuerRoots = [][]byte{newOwnerTestCA(t, now).cert.Raw}
		if _, e = peer.VerifyCurrentOwner(changed); e == nil {
			t.Fatal("removed root retained on existing TLS")
		}
		changed = config
		changed.Configuration.Suspended = true
		if _, e = peer.VerifyCurrentOwner(changed); e == nil {
			t.Fatal("suspended configuration accepted")
		}
		changed = config
		changed.FreshUntil = clock
		if _, e = peer.VerifyCurrentOwner(changed); e == nil {
			t.Fatal("stale configuration accepted")
		}
	}
	// Later mutation of the caller's parsed fields and DER cannot corrupt the
	// independent snapshot retained for a live request or a reused connection.
	response.TLS.PeerCertificates[0].Raw[0] ^= 1
	response.TLS.PeerCertificates[0].DNSNames[0] = "foreign"
	response.TLS.VerifiedChains[0] = nil
	if _, e = serverPeer.OwnerCertificate(); e != nil {
		t.Fatal("caller mutated snapshot", e)
	}
	clock = now.Add(21 * time.Minute)
	for _, peer := range []*OwnerConnection{serverPeer, clientPeer} {
		if _, e = peer.OwnerCertificate(); e == nil {
			t.Fatal("expired certificate survived connection reuse")
		}
	}
	var absent *OwnerConnection
	if _, e = absent.VerifyCurrentOwner(value.OwnerConfigurationObservation{}); e == nil {
		t.Fatal("nil connection accepted")
	}
}
