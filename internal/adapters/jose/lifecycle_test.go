package jose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

func lifecycleFixture() value.LifecycleDecision {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	return value.LifecycleDecision{ID: id, RootID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, Sequence: 1, RegistrationDigest: artifact.Digest{1}, PolicyRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{2}}, Policies: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{3}}}, Origins: []artifact.RetentionRule{{UID: "baseline", Generation: 1, Digest: artifact.Digest{3}}}, Previous: value.Deadlines{AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, Effective: value.Deadlines{AnchorAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), DeleteBy: now.Add(time.Minute)}, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
}
func TestLifecycleDetachedSignaturesBindPurposeRootAndHistoricalKey(t *testing.T) {
	ctx := context.Background()
	r := lifecycleFixture()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := NewLifecycleSignatures(r.RootID, "key-1", priv, map[string]ed25519.PublicKey{"key-1": pub})
	if err != nil {
		t.Fatal(err)
	}
	// The constructor freezes caller-owned material.
	clear(priv)
	clear(pub)
	b, err := s.SignLifecycle(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Split(string(b), ".")[1] != "" || bytes.Contains(b, []byte(r.Location.ArtifactID)) {
		t.Fatal("unencrypted decision in signature")
	}
	if err = s.VerifyLifecycle(ctx, r, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*value.LifecycleDecision){func(d *value.LifecycleDecision) { d.Sequence++ }, func(d *value.LifecycleDecision) { d.Target.PodUID = "other" }, func(d *value.LifecycleDecision) { d.Effective.DeleteBy = d.Effective.DeleteBy.Add(time.Second) }, func(d *value.LifecycleDecision) { d.RegistrationDigest[0]++ }, func(d *value.LifecycleDecision) { d.ValidUntil = d.ValidUntil.Add(time.Second) }} {
		bad := r
		change(&bad)
		if s.VerifyLifecycle(ctx, bad, b) == nil {
			t.Fatal("modified decision accepted")
		}
	}
	parts := strings.Split(string(b), ".")
	for _, header := range []string{`{"alg":"EdDSA","typ":"asservat-retention-lifecycle+jws","kid":"key-1"}`, `{"alg":"Ed25519","typ":"asservat-internal-work+jws","kid":"key-1"}`, `{"alg":"Ed25519","typ":"asservat-retention-lifecycle+jws","kid":"key-1","jku":"https://evil.invalid"}`, `{"alg":"Ed25519","typ":"asservat-retention-lifecycle+jws","kid":"key-1","kid":"key-1"}`} {
		bad := []byte(base64.RawURLEncoding.EncodeToString([]byte(header)) + ".." + parts[2])
		if s.VerifyLifecycle(ctx, r, bad) == nil {
			t.Fatal("header confusion")
		}
	}
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	rotated, err := NewLifecycleSignatures(r.RootID, "key-2", priv2, map[string]ed25519.PublicKey{"key-1": s.public["key-1"], "key-2": pub2})
	if err != nil {
		t.Fatal(err)
	}
	if err = rotated.VerifyLifecycle(ctx, r, b); err != nil {
		t.Fatal("old journal no longer verifiable", err)
	}
	readOnly, err := NewLifecycleSignatures(r.RootID, "", nil, map[string]ed25519.PublicKey{"key-1": s.public["key-1"]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readOnly.SignLifecycle(ctx, r); err == nil {
		t.Fatal("verifier can sign")
	}
	if readOnly.VerifyLifecycle(ctx, r, append(b, '.')) == nil {
		t.Fatal("extra framing")
	}
}

// ADR-195 step 5b: a remote signer (a pinned Transit key in production) yields
// the same detached compact signature, verified with its pinned public key.
func TestLifecycleRemoteSignerMatchesPinnedKey(t *testing.T) {
	ctx := context.Background()
	r := lifecycleFixture()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	remote, err := NewRemoteLifecycleSignatures(r.RootID, "lifecycle-v1", map[string]ed25519.PublicKey{"lifecycle-v1": pub}, func(context.Context) crypto.Signer { return priv })
	if err != nil {
		t.Fatal(err)
	}
	b, err := remote.SignLifecycle(ctx, r)
	if err != nil || remote.VerifyLifecycle(ctx, r, b) != nil {
		t.Fatal("remote signature", err)
	}
	verifier, _ := NewLifecycleSignatures(r.RootID, "", nil, map[string]ed25519.PublicKey{"lifecycle-v1": pub})
	if verifier.VerifyLifecycle(ctx, r, b) != nil {
		t.Fatal("pinned public key rejected the remote signature")
	}
	if _, err = NewRemoteLifecycleSignatures(r.RootID, "absent", map[string]ed25519.PublicKey{"lifecycle-v1": pub}, func(context.Context) crypto.Signer { return priv }); err == nil {
		t.Fatal("active key without a pinned public key accepted")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _ := NewRemoteLifecycleSignatures(r.RootID, "lifecycle-v1", map[string]ed25519.PublicKey{"lifecycle-v1": other}, func(context.Context) crypto.Signer { return priv })
	if b, err = wrong.SignLifecycle(ctx, r); err == nil && wrong.VerifyLifecycle(ctx, r, b) == nil {
		t.Fatal("signature verified against another pinned key")
	}
}
