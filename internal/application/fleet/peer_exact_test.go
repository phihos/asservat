package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

type exactPeerFixture struct {
	legacy, exact int
	got           value.PeerCertificate
	out           value.PeerRegistration
	err           error
	block         func()
}

func (f *exactPeerFixture) PeerRegistration(context.Context, value.PeerBinding) (value.PeerRegistration, error) {
	f.legacy++
	return f.out, nil
}
func (f *exactPeerFixture) PeerCertificateRegistration(_ context.Context, c value.PeerCertificate) (value.PeerRegistration, error) {
	f.exact++
	f.got = c
	if f.block != nil {
		f.block()
	}
	return f.out, f.err
}
func TestConnectorExactLeafRegistryDoesNotFallBackOrRenew(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	b := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	leaf := value.PeerCertificate{Binding: b, Digest: artifact.Digest{1}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	for _, mode := range []string{"current", "denied", "wrong-leaf", "late", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			clock := now
			ctx, end := context.WithCancel(context.Background())
			defer end()
			f := &exactPeerFixture{out: value.PeerRegistration{Binding: b, Enabled: true, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{2}}, Certificates: []value.PeerCertificate{leaf}, ObservedAt: now, FreshUntil: now.Add(time.Second)}}
			switch mode {
			case "denied":
				f.err = value.ErrDenied
			case "wrong-leaf":
				f.out.Certificates[0].Digest = artifact.Digest{3}
			case "late":
				f.block = func() { clock = now.Add(time.Second) }
			case "cancelled":
				f.block = end
			}
			got, e := (PeerAuthenticator{Registry: f, Now: func() time.Time { return clock }}).AuthenticatePeer(ctx, leaf)
			if f.exact != 1 || f.legacy != 0 || f.got != leaf {
				t.Fatal("exact current leaf was not the sole lookup")
			}
			if mode == "current" {
				if e != nil || got.Certificate != leaf || !got.ValidUntil.Equal(now.Add(time.Second)) {
					t.Fatal("current exact registration", e)
				}
			} else if e == nil {
				t.Fatal("invalid exact registration fell back or renewed")
			}
		})
	}
}
