package fleet

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type peerRegistryFunc func(context.Context, value.PeerBinding) (value.PeerRegistration, error)

func (f peerRegistryFunc) PeerRegistration(c context.Context, p value.PeerBinding) (value.PeerRegistration, error) {
	return f(c, p)
}
func TestPeerCurrentRegistration(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"valid", "revoked", "epoch", "certificate", "stale", "expires-during-read", "duplicate-cert"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			c := value.PeerCertificate{Binding: value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}, Digest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(time.Hour)}
			r := value.PeerRegistration{Binding: c.Binding, Revision: identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}, Enabled: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Certificates: []value.PeerCertificate{c}}
			switch mode {
			case "revoked":
				r.Enabled = false
			case "epoch":
				r.Binding.IssuerEpoch = "22222222-2222-4222-8222-222222222222"
			case "certificate":
				r.Certificates[0].Digest = artifact.Digest{2}
			case "stale":
				r.ObservedAt = now.Add(-5 * time.Second)
				r.FreshUntil = now
			case "duplicate-cert":
				r.Certificates = append(r.Certificates, c)
			}
			a := PeerAuthenticator{Now: func() time.Time { return now }, Registry: peerRegistryFunc(func(context.Context, value.PeerBinding) (value.PeerRegistration, error) {
				if mode == "expires-during-read" {
					now = now.Add(5 * time.Second)
				}
				return r, nil
			})}
			peer, err := a.AuthenticatePeer(context.Background(), c)
			if mode == "valid" {
				if err != nil || !peer.ValidUntil.Equal(r.FreshUntil) {
					t.Fatal(peer, err)
				}
			} else if err == nil {
				t.Fatal("invalid registration trusted")
			}
		})
	}
}
