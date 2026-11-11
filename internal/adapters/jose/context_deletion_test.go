package jose

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func deletionSignatureFixture() value.ContextDeletionCheckpoint {
	id := "10000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	return value.ContextDeletionCheckpoint{RootID: id, CaptureID: id, StoreID: id, InstallationID: id, IssuerEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, RegistrationDigest: artifact.Digest{1}, WriterDigest: artifact.Digest{2}, PostmasterAt: now.Add(-time.Hour), DatabaseOID: 42, PurgeFence: 1, PurgedAt: now}
}
func TestDeletionSignatureBindsWriterPurgeAndIncarnation(t *testing.T) {
	r := deletionSignatureFixture()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := NewContextDeletionSignatures(r.RootID, "dedicated-deletion", key, map[string]ed25519.PublicKey{"dedicated-deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sig, err := signer.SignContextDeletion(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = signer.VerifyContextDeletion(ctx, r, sig); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*value.ContextDeletionCheckpoint){func(r *value.ContextDeletionCheckpoint) { r.WriterDigest[0]++ }, func(r *value.ContextDeletionCheckpoint) { r.PurgeFence++ }, func(r *value.ContextDeletionCheckpoint) { r.DatabaseOID++ }, func(r *value.ContextDeletionCheckpoint) { r.PostmasterAt = r.PostmasterAt.Add(time.Second) }, func(r *value.ContextDeletionCheckpoint) {
		r.Location.AttemptID = "20000000-0000-4000-8000-000000000001"
	}} {
		bad := r
		change(&bad)
		if signer.VerifyContextDeletion(ctx, bad, sig) == nil {
			t.Fatal("foreign cleanup acknowledged")
		}
	}
	historical, err := NewContextDeletionSignatures(r.RootID, "", nil, map[string]ed25519.PublicKey{"dedicated-deletion": pub})
	if err != nil {
		t.Fatal(err)
	}
	if err = historical.VerifyContextDeletion(ctx, r, sig); err != nil {
		t.Fatal(err)
	}
	if _, err = historical.SignContextDeletion(ctx, r); err == nil {
		t.Fatal("read-only key signed")
	}
}

func TestSharedProviderKeyBindsDeletionAndLifecyclePurposeAndRoot(t *testing.T) {
	ctx := context.Background()
	deletion := deletionSignatureFixture()
	lifecycle := lifecycleFixture()
	lifecycle.RootID = deletion.RootID
	const keyID = "retention-worker"
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{keyID: pub}
	calls := 0
	provider := func(ctx context.Context) crypto.Signer {
		return retirementRequestSigner{ctx: ctx, key: key, calls: &calls}
	}
	deletionSigner, err := NewRemoteContextDeletionSignatures(deletion.RootID, keyID, keys, provider)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleSigner, err := NewRemoteLifecycleSignatures(lifecycle.RootID, keyID, keys, provider)
	if err != nil {
		t.Fatal(err)
	}
	deletionSig, err := deletionSigner.SignContextDeletion(ctx, deletion)
	if err != nil || deletionSigner.VerifyContextDeletion(ctx, deletion, deletionSig) != nil {
		t.Fatal("shared provider key failed deletion round trip", err)
	}
	lifecycleSig, err := lifecycleSigner.SignLifecycle(ctx, lifecycle)
	if err != nil || lifecycleSigner.VerifyLifecycle(ctx, lifecycle, lifecycleSig) != nil {
		t.Fatal("shared provider key failed lifecycle round trip", err)
	}
	if calls != 2 {
		t.Fatal("expected one signing call per record", calls)
	}
	if lifecycleSigner.VerifyLifecycle(ctx, lifecycle, deletionSig) == nil {
		t.Fatal("deletion signature verified for lifecycle")
	}
	if deletionSigner.VerifyContextDeletion(ctx, deletion, lifecycleSig) == nil {
		t.Fatal("lifecycle signature verified for deletion")
	}

	const foreignRoot = "20000000-0000-4000-8000-000000000001"
	foreignDeletion, err := NewContextDeletionSignatures(foreignRoot, "", nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	foreignLifecycle, err := NewLifecycleSignatures(foreignRoot, "", nil, keys)
	if err != nil {
		t.Fatal(err)
	}
	if foreignDeletion.VerifyContextDeletion(ctx, deletion, deletionSig) == nil {
		t.Fatal("deletion signature verified under a different root")
	}
	if foreignLifecycle.VerifyLifecycle(ctx, lifecycle, lifecycleSig) == nil {
		t.Fatal("lifecycle signature verified under a different root")
	}
}
