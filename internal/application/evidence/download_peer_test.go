package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"testing"
	"time"
)

type peerProofFunc func(context.Context, string, value.KeyPeer) (value.KeyWorkerProof, error)

func (f peerProofFunc) ReadDownloadPeerProof(c context.Context, s string, p value.KeyPeer) (value.KeyWorkerProof, error) {
	return f(c, s, p)
}

type peerLedgerFunc func(context.Context, string, artifact.DownloadAuthority, string, int64, value.KeyScope, value.KeyPeer, value.KeyWorkerProof) error

func (f peerLedgerFunc) BindAttestedDownloadKeys(c context.Context, s string, a artifact.DownloadAuthority, b string, g int64, k value.KeyScope, p value.KeyPeer, o value.KeyWorkerProof) error {
	return f(c, s, a, b, g, k, p, o)
}
func TestDownloadPeerProofCannotRenewOrSubstituteAuthority(t *testing.T) {
	for _, mode := range []string{"valid", "missing-source", "source-failed", "wrong-session", "wrong-certificate", "expired-after-read", "expired-after-bind", "cancelled-after-bind"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := downloadWorkerTest(t)
			base := time.Now().UTC()
			f.now = base
			f.a.CheckedAt = base
			f.a.ValidUntil = base.Add(5 * time.Second)
			scope := value.KeyScope{InstallationID: f.s.ID, Purpose: "artifact", KeyID: "evidence"}
			peer := value.KeyPeer{InstallationID: f.s.ID, PeerID: f.s.ID, Role: "acquisition", Certificate: artifact.Digest{1}, NotBefore: base.Add(-time.Minute), NotAfter: base.Add(time.Minute)}
			proof := value.KeyWorkerProof{Binding: value.KeyWorkerBinding{InstallationID: f.s.ID, DownloadID: f.s.ID, ClusterID: f.s.ID, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "reader", ServiceAccountUID: "account", Job: "download", JobUID: "job", Pod: "worker", PodUID: peer.PeerID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}}, Peer: peer, TokenDigest: artifact.Digest{3}, ObservedAt: base, FreshUntil: base.Add(time.Second)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			service := AttestedDownloadKeyGrants{Now: func() time.Time { return f.now }}
			service.Proofs = peerProofFunc(func(context.Context, string, value.KeyPeer) (value.KeyWorkerProof, error) {
				p := proof
				switch mode {
				case "source-failed":
					return p, artifact.ErrInvalid
				case "wrong-session":
					p.Binding.DownloadID = "22222222-2222-4222-8222-222222222222"
				case "wrong-certificate":
					p.Peer.Certificate[0]++
				case "expired-after-read":
					f.now = base.Add(time.Second)
				}
				return p, nil
			})
			if mode == "missing-source" {
				service.Proofs = nil
			}
			service.Ledger = peerLedgerFunc(func(c context.Context, s string, a artifact.DownloadAuthority, b string, g int64, k value.KeyScope, p value.KeyPeer, o value.KeyWorkerProof) error {
				calls++
				until, ok := c.Deadline()
				if !ok || until.After(proof.FreshUntil) || s != f.s.ID || p != peer || k != scope || o.Binding != proof.Binding {
					t.Fatal("binding lost original proof/scope")
				}
				if mode == "expired-after-bind" {
					f.now = base.Add(time.Second)
				}
				if mode == "cancelled-after-bind" {
					cancel()
				}
				return nil
			})
			e := service.BindDownloadKeys(ctx, f.s.ID, f.a, f.s.ID, 1, scope, peer)
			if mode == "valid" {
				if e != nil || calls != 1 {
					t.Fatal("valid proof rejected", e, calls)
				}
			} else if e == nil {
				t.Fatal("unsafe proof accepted")
			}
			if mode != "valid" && mode != "expired-after-bind" && mode != "cancelled-after-bind" && calls != 0 {
				t.Fatal("ledger used before valid proof")
			}
		})
	}
}
