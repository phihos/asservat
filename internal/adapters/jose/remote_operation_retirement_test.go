package jose

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
)

func remoteRetirementFixture() value.OperationRetirement {
	now := time.Now().UTC().Truncate(time.Microsecond)
	const id = "10000000-0000-4000-8000-000000000001"
	return value.OperationRetirement{RootID: id, OperationID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, PostmasterAt: now.Add(-time.Hour), DatabaseOID: 42, ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2}, PurgeFence: 1, PurgedAt: now.Add(-time.Second), CertificateWriteUntil: now.Add(10 * time.Second), CertificatePurgeAt: now.Add(time.Hour), LiveRetireBy: now.Add(2 * time.Hour)}
}

type retirementRequestSigner struct {
	ctx     context.Context
	key     ed25519.PrivateKey
	blocked bool
	calls   *int
}

func (s retirementRequestSigner) Public() crypto.PublicKey { return s.key.Public() }
func (s retirementRequestSigner) Sign(_ io.Reader, p []byte, o crypto.SignerOpts) ([]byte, error) {
	*s.calls++
	if s.blocked {
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	return s.key.Sign(rand.Reader, p, o)
}

func TestRemoteOperationRetirementPreservesExistingDetachedVerification(t *testing.T) {
	r := remoteRetirementFixture()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := NewRemoteOperationRetirementSignatures(r.RootID, "retirement/v1", map[string]ed25519.PublicKey{"retirement/v1": pub}, func(ctx context.Context) crypto.Signer { return retirementRequestSigner{ctx, key, false, &calls} })
	if err != nil {
		t.Fatal(err)
	}
	parent, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	signature, err := s.SignOperationRetirement(parent, r)
	if err != nil || calls != 1 {
		t.Fatal("original provider signing failed", err, calls)
	}
	verifier, err := NewOperationRetirementSignatures(r.RootID, "", nil, map[string]ed25519.PublicKey{"retirement/v1": pub})
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.VerifyOperationRetirement(parent, r, signature); err != nil {
		t.Fatal(err)
	}
	r.DatabaseOID++
	if verifier.VerifyOperationRetirement(parent, r, signature) == nil {
		t.Fatal("retirement signature crossed original database incarnation")
	}
}

func TestRemoteOperationRetirementKeepsCallerAndCertificateDeadlines(t *testing.T) {
	for _, mode := range []string{"caller", "certificate", "expired", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			r := remoteRetirementFixture()
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
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
			if mode == "certificate" {
				r.CertificateWriteUntil = time.Now().Add(40 * time.Millisecond).UTC().Truncate(time.Microsecond)
				want = r.CertificateWriteUntil
			}
			if mode == "expired" {
				r.CertificateWriteUntil = time.Now().Add(-time.Millisecond).UTC().Truncate(time.Microsecond)
			}
			if mode == "wrong-key" {
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			}
			s, err := NewRemoteOperationRetirementSignatures(r.RootID, "retirement/v1", map[string]ed25519.PublicKey{"retirement/v1": pub}, func(live context.Context) crypto.Signer {
				until, ok := live.Deadline()
				if !ok || !until.Equal(want) {
					t.Errorf("original earliest deadline changed: got%v want%v", until, want)
				}
				return retirementRequestSigner{live, key, true, &calls}
			})
			if err != nil {
				t.Fatal(err)
			}
			if b, e := s.SignOperationRetirement(ctx, r); e == nil || b != nil {
				t.Fatal("expired/blocked/unpinned signing returned a certificate")
			}
			if (mode == "expired" || mode == "wrong-key") && calls != 0 {
				t.Fatal("provider used before original checks")
			}
			if (mode == "caller" || mode == "certificate") && calls != 1 {
				t.Fatal("original provider request retried or never made", calls)
			}
		})
	}
}
