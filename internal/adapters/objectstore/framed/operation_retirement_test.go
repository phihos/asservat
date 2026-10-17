package framed

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestOperationRetirementRequiresExactEncryptedSignedCheckpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := testBinding.ClusterID
	r := value.OperationRetirement{RootID: id, OperationID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, PostmasterAt: now.Add(-time.Hour), DatabaseOID: 42, ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2}, PurgeFence: 1, PurgedAt: now, CertificateWriteUntil: now.Add(10 * time.Second), CertificatePurgeAt: now.Add(time.Hour), LiveRetireBy: now.Add(2 * time.Hour)}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := jose.NewOperationRetirementSignatures(id, "deletion", private, map[string]ed25519.PublicKey{"deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	k := keys(t)
	ctx := context.Background()
	cipher, err := SealOperationRetirement(ctx, k, signer, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyOperationRetirement(ctx, k, signer, r, cipher); err != nil {
		t.Fatal(err)
	}
	var original signedOperationRetirement
	if err = json.Unmarshal(cipher, &original); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*signedOperationRetirement){func(v *signedOperationRetirement) { v.Signature = nil }, func(v *signedOperationRetirement) { v.Encrypted = []byte("tampered") }, func(v *signedOperationRetirement) { v.Format = "asservat-retention-lifecycle/v1" }} {
		v := original
		change(&v)
		b, _ := json.Marshal(v)
		if VerifyOperationRetirement(ctx, k, signer, r, b) == nil {
			t.Fatal("unverified encrypted checkpoint accepted")
		}
	}
	r.DatabaseOID++
	if VerifyOperationRetirement(ctx, k, signer, r, cipher) == nil {
		t.Fatal("checkpoint replayed across incarnation")
	}
	k.fail = true
	if _, err = SealOperationRetirement(ctx, k, signer, r); err == nil {
		t.Fatal("key failure wrote plaintext")
	}
}
