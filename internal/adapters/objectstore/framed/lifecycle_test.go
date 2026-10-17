package framed

import (
	"asservat.local/asservat/internal/adapters/jose"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestLifecycleRequiresBothSignatureAndEncryptedRecord(t *testing.T) {
	ctx := context.Background()
	k := keys(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := testBinding.ClusterID
	r := value.LifecycleDecision{ID: id, RootID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, Sequence: 1, RegistrationDigest: artifact.Digest{1}, PolicyRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{2}}, Policies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{3}}}, Origins: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{3}}}, Previous: value.Deadlines{AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, Effective: value.Deadlines{AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), DeleteBy: now.Add(time.Minute)}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := jose.NewLifecycleSignatures(id, "test", priv, map[string]ed25519.PublicKey{"test": pub})
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealLifecycle(ctx, k, signer, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyLifecycle(ctx, k, signer, r, b); err != nil {
		t.Fatal(err)
	}
	var original signedLifecycle
	if err = json.Unmarshal(b, &original); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*signedLifecycle){func(v *signedLifecycle) { v.Signature = nil }, func(v *signedLifecycle) { v.Signature = []byte("invalid") }, func(v *signedLifecycle) { v.Format = "asservat-download-outcome/v1" }, func(v *signedLifecycle) { v.Encrypted = []byte("corrupt") }} {
		bad := original
		change(&bad)
		encoded, _ := json.Marshal(bad)
		if VerifyLifecycle(ctx, k, signer, r, encoded) == nil {
			t.Fatal("unsigned/corrupt journal accepted")
		}
	}
	different := r
	different.Sequence++
	if VerifyLifecycle(ctx, k, signer, different, b) == nil {
		t.Fatal("different decision accepted")
	}
	k.fail = true
	if _, err = SealLifecycle(ctx, k, signer, r); err == nil {
		t.Fatal("plaintext fallback")
	}
	if VerifyLifecycle(ctx, unavailableLifecycleOpener{}, signer, r, b) == nil {
		t.Fatal("KMS failure bypassed")
	}
}

type unavailableLifecycleOpener struct{}

func (unavailableLifecycleOpener) Open(context.Context, artifact.SealedKey, []byte) ([]byte, error) {
	return nil, context.DeadlineExceeded
}
