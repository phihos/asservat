package framed

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestContextDeletionRequiresExactEncryptedSignedCheckpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := testBinding.ClusterID
	r := value.ContextDeletionCheckpoint{RootID: id, CaptureID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, RegistrationDigest: artifact.Digest{1}, WriterDigest: artifact.Digest{2}, PostmasterAt: now.Add(-time.Hour), DatabaseOID: 42, PurgeFence: 1, PurgedAt: now}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := jose.NewContextDeletionSignatures(id, "deletion", private, map[string]ed25519.PublicKey{"deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	k := keys(t)
	ctx := context.Background()
	cipher, err := SealContextDeletion(ctx, k, signer, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyContextDeletion(ctx, k, signer, r, cipher); err != nil {
		t.Fatal(err)
	}
	var original signedContextDeletion
	if err = json.Unmarshal(cipher, &original); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*signedContextDeletion){func(v *signedContextDeletion) { v.Signature = nil }, func(v *signedContextDeletion) { v.Encrypted = []byte("tampered") }, func(v *signedContextDeletion) { v.Format = "asservat-retention-lifecycle/v1" }} {
		v := original
		change(&v)
		b, _ := json.Marshal(v)
		if VerifyContextDeletion(ctx, k, signer, r, b) == nil {
			t.Fatal("unverified encrypted checkpoint accepted")
		}
	}
	r.DatabaseOID++
	if VerifyContextDeletion(ctx, k, signer, r, cipher) == nil {
		t.Fatal("checkpoint replayed across incarnation")
	}
	k.fail = true
	if _, err = SealContextDeletion(ctx, k, signer, r); err == nil {
		t.Fatal("key failure wrote plaintext")
	}
}
