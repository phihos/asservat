package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

// lyingSigner reports one public key and signs with another.
type lyingSigner struct {
	public ed25519.PublicKey
	key    ed25519.PrivateKey
}

func (s lyingSigner) Public() crypto.PublicKey { return s.public }
func (s lyingSigner) Sign(_ io.Reader, p []byte, o crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand.Reader, p, o)
}

// ADR-205 decision 6: a provider-held key produces exactly the in-process
// detached JWS, so either side verifies the other's records.
func TestRemoteContextDeletionMatchesInProcessSignatures(t *testing.T) {
	r := deletionSignatureFixture()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"deletion-v1": pub}
	calls := 0
	remote, err := NewRemoteContextDeletionSignatures(r.RootID, "deletion-v1", keys, func(ctx context.Context) crypto.Signer { return retirementRequestSigner{ctx, key, false, &calls} })
	if err != nil {
		t.Fatal(err)
	}
	local, err := NewContextDeletionSignatures(r.RootID, "deletion-v1", key, keys)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	remoteSig, err := remote.SignContextDeletion(ctx, r)
	if err != nil || calls != 1 {
		t.Fatal("provider signing failed", err, calls)
	}
	localSig, err := local.SignContextDeletion(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remoteSig, localSig) {
		t.Fatal("remote and in-process signatures differ")
	}
	if err = local.VerifyContextDeletion(ctx, r, remoteSig); err != nil {
		t.Fatal("in-process verifier refused a remote signature", err)
	}
	if err = remote.VerifyContextDeletion(ctx, r, localSig); err != nil {
		t.Fatal("remote verifier refused an in-process signature", err)
	}
	changed := r
	changed.PurgeFence++
	if remote.VerifyContextDeletion(ctx, changed, remoteSig) == nil {
		t.Fatal("signature verified for another record")
	}
	// The key signs only deletion records: an operation retirement signature
	// by the same key and key ID never verifies as one.
	retirement, err := NewRemoteOperationRetirementSignatures(r.RootID, "deletion-v1", keys, func(ctx context.Context) crypto.Signer { return retirementRequestSigner{ctx, key, false, &calls} })
	if err != nil {
		t.Fatal(err)
	}
	other, err := retirement.SignOperationRetirement(ctx, remoteRetirementFixture())
	if err != nil {
		t.Fatal(err)
	}
	if remote.VerifyContextDeletion(ctx, r, other) == nil || local.VerifyContextDeletion(ctx, r, other) == nil {
		t.Fatal("operation retirement signature verified as a deletion record")
	}
	// Records signed by an earlier version verify against its retained key.
	old, oldKey, _ := ed25519.GenerateKey(rand.Reader)
	earlier, err := NewContextDeletionSignatures(r.RootID, "deletion-v0", oldKey, map[string]ed25519.PublicKey{"deletion-v0": old})
	if err != nil {
		t.Fatal(err)
	}
	oldSig, err := earlier.SignContextDeletion(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	both, err := NewRemoteContextDeletionSignatures(r.RootID, "deletion-v1", map[string]ed25519.PublicKey{"deletion-v0": old, "deletion-v1": pub}, func(ctx context.Context) crypto.Signer { return retirementRequestSigner{ctx, key, false, &calls} })
	if err != nil || both.VerifyContextDeletion(ctx, r, oldSig) != nil || remote.VerifyContextDeletion(ctx, r, oldSig) == nil {
		t.Fatal("retained public keys not honoured", err)
	}
}

func TestRemoteContextDeletionRefusesUnpinnedKeysAndKeepsDeadlines(t *testing.T) {
	r := deletionSignatureFixture()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"deletion-v1": pub}
	signer := func(context.Context) crypto.Signer { return nil }
	for name, build := range map[string]func() (*RemoteContextDeletionSignatures, error){
		"nil-signer": func() (*RemoteContextDeletionSignatures, error) {
			return NewRemoteContextDeletionSignatures(r.RootID, "deletion-v1", keys, nil)
		},
		"unknown-kid": func() (*RemoteContextDeletionSignatures, error) {
			return NewRemoteContextDeletionSignatures(r.RootID, "deletion-v2", keys, signer)
		},
		"root": func() (*RemoteContextDeletionSignatures, error) {
			return NewRemoteContextDeletionSignatures("root", "deletion-v1", keys, signer)
		},
	} {
		if s, err := build(); err == nil || s != nil {
			t.Fatal("invalid remote signer accepted", name)
		}
	}
	for _, mode := range []string{"wrong-key", "lying-provider", "other-root", "caller", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want, _ := ctx.Deadline()
			if mode == "caller" {
				var c context.CancelFunc
				ctx, c = context.WithTimeout(ctx, 40*time.Millisecond)
				defer c()
				want, _ = ctx.Deadline()
			}
			if mode == "cancelled" {
				var c context.CancelFunc
				ctx, c = context.WithCancel(ctx)
				c()
			}
			record := r
			if mode == "other-root" {
				record.RootID = "20000000-0000-4000-8000-000000000001"
			}
			s, err := NewRemoteContextDeletionSignatures(r.RootID, "deletion-v1", keys, func(live context.Context) crypto.Signer {
				if until, ok := live.Deadline(); !ok || !until.Equal(want) {
					t.Errorf("original caller deadline changed: got %v want %v", until, want)
				}
				switch mode {
				case "wrong-key":
					return retirementRequestSigner{live, otherKey, false, &calls}
				case "lying-provider":
					calls++
					return lyingSigner{pub, otherKey}
				}
				return retirementRequestSigner{live, key, true, &calls}
			})
			if err != nil {
				t.Fatal(err)
			}
			if b, e := s.SignContextDeletion(ctx, record); e == nil || b != nil {
				t.Fatal("unpinned, foreign or blocked signing returned a signature")
			}
			if (mode == "wrong-key" || mode == "other-root" || mode == "cancelled") && calls != 0 {
				t.Fatal("provider used before original checks", calls)
			}
			if (mode == "caller" || mode == "lying-provider") && calls != 1 {
				t.Fatal("provider request retried or never made", calls)
			}
		})
	}
}
