package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	authvalue "asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

func connectorKeyState(t *testing.T, c *tls.Certificate) *tls.ConnectionState {
	t.Helper()
	var chain []*x509.Certificate
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, cert)
	}
	return &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: chain, VerifiedChains: [][]*x509.Certificate{chain}}
}

// ADR-176: a staged connector's activated client leaf is the artifact key
// service's collector; the union selects the verifier by URI form only, and
// the peer resolves from its staged profile per request (ADR-198).
func TestConnectorClientLeafIsTheArtifactCollector(t *testing.T) {
	cf := newConnectorPairFixture(t)
	connector := cf.owner()
	if err := connector.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	leaf, err := connector.snapshot(0) // the current client leaf, as presented in a handshake
	if err != nil {
		t.Fatal(err)
	}
	state := connectorKeyState(t, leaf)
	staged, reads := cf.profile, 0
	read := func(_ context.Context, p value.ClusterCredentialProfile) (value.ConnectorCredentialProfile, error) {
		reads++
		b := staged.Binding
		if p != (value.ClusterCredentialProfile{RootID: staged.RootID, PeerID: b.PeerID, InstallationID: b.InstallationID, ClusterID: b.ClusterID}) {
			return value.ConnectorCredentialProfile{}, value.ErrUnavailable
		}
		return staged, nil
	}
	verifier, err := NewConnectorKeyPeerVerifier(cf.profile.Binding.InstallationID, cf.profile.RootID, read, cf.clock)
	if err != nil {
		t.Fatal(err)
	}
	keyClients, err := NewKeyPeerVerifier(cf.clientCA.roots, cf.profile.Binding.InstallationID, cf.clock)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := KeyPeerUnion{KeyClients: keyClients, Connectors: verifier}.Verify(state)
	if err != nil {
		t.Fatal("connector client leaf", err)
	}
	if peer.Role != "collector" || peer.PeerID != cf.profile.Binding.PeerID || peer.Certificate != artifact.Digest(sha256.Sum256(state.PeerCertificates[0].Raw)) || !peer.CanRequest(authvalue.KeyScope{InstallationID: peer.InstallationID, Purpose: "artifact", KeyID: "k"}, "wrap") {
		t.Fatal("connector leaf mapped to the wrong key peer", peer)
	}
	if peer.CanRequest(authvalue.KeyScope{InstallationID: peer.InstallationID, Purpose: "artifact", KeyID: "k"}, "unwrap") {
		t.Fatal("collector may unwrap")
	}
	if _, err = (KeyPeerUnion{KeyClients: keyClients}).Verify(state); err == nil {
		t.Fatal("connector leaf accepted without a connector verifier")
	}
	other, err := NewConnectorKeyPeerVerifier("10000000-0000-4000-8000-0000000000ff", cf.profile.RootID, read, cf.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (KeyPeerUnion{KeyClients: keyClients, Connectors: other}).Verify(state); err == nil {
		t.Fatal("leaf of another installation accepted")
	}
	otherRoot, err := NewConnectorKeyPeerVerifier(cf.profile.Binding.InstallationID, "10000000-0000-4000-8000-0000000000fe", read, cf.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (KeyPeerUnion{KeyClients: keyClients, Connectors: otherRoot}).Verify(state); err == nil {
		t.Fatal("leaf accepted under another permission root")
	}
	staged.Suspended = true
	if _, err = (KeyPeerUnion{KeyClients: keyClients, Connectors: verifier}).Verify(state); err == nil {
		t.Fatal("suspended staged profile accepted")
	}
	staged = cf.profile
	staged.Binding.IssuerEpoch = "10000000-0000-4000-8000-0000000000fd"
	if _, err = (KeyPeerUnion{KeyClients: keyClients, Connectors: verifier}).Verify(state); err == nil {
		t.Fatal("profile of another issuer epoch accepted")
	}
	staged = cf.profile
	if reads < 4 {
		t.Fatal("staged profile not read per request", reads)
	}
	unverified := *state
	unverified.VerifiedChains = nil
	if _, err = (KeyPeerUnion{KeyClients: keyClients, Connectors: verifier}).Verify(&unverified); err == nil {
		t.Fatal("unverified TLS chain accepted")
	}
}

type keyAuthorityCall struct{ operation string }

func (k *keyAuthorityCall) Resolve(_ context.Context, _ authvalue.KeyPeer, r authvalue.KeyRequestInfo) (authvalue.KeyOperationPermit, error) {
	k.operation = r.Operation
	return authvalue.KeyOperationPermit{}, nil
}

func TestKeyOperationAuthorizersDispatchByOperation(t *testing.T) {
	wrap, unwrap := &keyAuthorityCall{}, &keyAuthorityCall{}
	a := app.KeyOperationAuthorizers{"wrap": wrap, "unwrap": unwrap}
	for _, op := range []string{"wrap", "unwrap"} {
		if _, err := a.Resolve(context.Background(), authvalue.KeyPeer{}, authvalue.KeyRequestInfo{Operation: op}); err != nil {
			t.Fatal(err)
		}
	}
	if wrap.operation != "wrap" || unwrap.operation != "unwrap" {
		t.Fatal("operation reached another authority")
	}
	if _, err := a.Resolve(context.Background(), authvalue.KeyPeer{}, authvalue.KeyRequestInfo{Operation: "sign"}); err == nil {
		t.Fatal("operation without an authority allowed")
	}
	// ADR-181: a role-specific authority takes precedence for that role only.
	verify := &keyAuthorityCall{}
	a["unwrap/verifier"] = verify
	unwrap.operation = ""
	if _, err := a.Resolve(context.Background(), authvalue.KeyPeer{Role: "verifier"}, authvalue.KeyRequestInfo{Operation: "unwrap"}); err != nil || verify.operation != "unwrap" || unwrap.operation != "" {
		t.Fatal("verifier unwrap reached another authority")
	}
	if _, err := a.Resolve(context.Background(), authvalue.KeyPeer{Role: "acquisition"}, authvalue.KeyRequestInfo{Operation: "unwrap"}); err != nil || unwrap.operation != "unwrap" {
		t.Fatal("acquisition unwrap lost its operation authority")
	}
}
