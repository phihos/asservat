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

func TestDownloadStopRetirementRequiresExactEncryptedSignedCheckpoint(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := testBinding.ClusterID
	r := value.DownloadStopRetirement{RootID: id, DownloadID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, Mode: "written", BindingDigest: artifact.Digest{3}, ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2}, PurgeFence: 1, PurgedAt: now, CertificateWriteUntil: now.Add(10 * time.Second), CertificatePurgeAt: now.Add(time.Hour), LiveRetireBy: now.Add(2 * time.Hour)}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := jose.NewDownloadStopRetirementSignatures(id, "deletion", private, map[string]ed25519.PublicKey{"deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jose.NewDownloadStopRetirementSignatures(id, "", nil, map[string]ed25519.PublicKey{"deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.SignDownloadStopRetirement(context.Background(), r); err == nil {
		t.Fatal("public verifier acquired signing ability")
	}
	k := keys(t)
	ctx := context.Background()
	cipher, err := SealDownloadStopRetirement(ctx, k, signer, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyDownloadStopRetirement(ctx, k, verifier, r, cipher); err != nil {
		t.Fatal(err)
	}
	var original signedDownloadStopRetirement
	if err = json.Unmarshal(cipher, &original); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*signedDownloadStopRetirement){func(v *signedDownloadStopRetirement) { v.Signature = nil }, func(v *signedDownloadStopRetirement) { v.Encrypted = []byte("tampered") }, func(v *signedDownloadStopRetirement) { v.Format = "asservat-retention-lifecycle/v1" }} {
		v := original
		change(&v)
		b, _ := json.Marshal(v)
		if VerifyDownloadStopRetirement(ctx, k, verifier, r, b) == nil {
			t.Fatal("unverified encrypted checkpoint accepted")
		}
	}
	r.BindingDigest[0]++
	if VerifyDownloadStopRetirement(ctx, k, verifier, r, cipher) == nil {
		t.Fatal("checkpoint replayed across binding")
	}
	k.fail = true
	if _, err = SealDownloadStopRetirement(ctx, k, signer, r); err == nil {
		t.Fatal("key failure wrote plaintext")
	}
}
