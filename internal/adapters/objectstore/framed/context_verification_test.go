package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestContextVerificationAuditPinsCopiesScopeAndPurpose(t *testing.T) {
	k := keys(t)
	ctx := context.Background()
	now := time.Now().UTC()
	r := audit.ContextVerification{RootID: testBinding.ClusterID, CaptureID: testBinding.ArtifactID, ArtifactID: testBinding.ArtifactID, AttemptID: testBinding.AttemptID, PermissionEpoch: testBinding.ClusterID, PermissionSequence: 1, ScopeDigest: artifact.Digest{1}, ExpectationDigest: artifact.Digest{2}, CopiesDigest: artifact.Digest{3}, IntentDigest: artifact.Digest{4}, AuthorityDigest: artifact.Digest{5}, VerifiedAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	b, err := SealContextVerification(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyContextVerification(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.ContextVerification){func(r *audit.ContextVerification) { r.CopiesDigest[0]++ }, func(r *audit.ContextVerification) { r.ExpectationDigest[0]++ }, func(r *audit.ContextVerification) { r.AuthorityDigest[0]++ }, func(r *audit.ContextVerification) { r.IntentDigest[0]++ }, func(r *audit.ContextVerification) { r.PermissionSequence++ }, func(r *audit.ContextVerification) { r.VerifiedAt = r.VerifiedAt.Add(time.Second) }} {
		changed := r
		change(&changed)
		if VerifyContextVerification(ctx, k, changed, b) == nil {
			t.Fatal("different verification authenticated")
		}
	}
	var envelope authorityEnvelope
	if json.Unmarshal(b, &envelope) != nil {
		t.Fatal("fixture")
	}
	envelope.Format = captureIntentFormat
	other, _ := json.Marshal(envelope)
	if verifyControlAudit(ctx, k, captureIntentFormat, r.RootID, r.CaptureID, r, other, 64<<10) == nil {
		t.Fatal("cross-purpose audit accepted")
	}
	envelope.Format = contextVerificationFormat
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
	other, _ = json.Marshal(envelope)
	if VerifyContextVerification(ctx, k, r, other) == nil {
		t.Fatal("corruption accepted")
	}
	k.fail = true
	if _, err = SealContextVerification(ctx, k, r); err == nil {
		t.Fatal("unencrypted fallback")
	}
}

func TestContextVerificationNativeLengthAuditCompatibility(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	r := audit.ContextVerification{RootID: testBinding.ClusterID, CaptureID: testBinding.ArtifactID, ArtifactID: testBinding.ArtifactID, AttemptID: testBinding.AttemptID, PermissionEpoch: testBinding.ClusterID, PermissionSequence: 1, ScopeDigest: artifact.Digest{1}, ExpectationDigest: artifact.Digest{2}, CopiesDigest: artifact.Digest{3}, IntentDigest: artifact.Digest{4}, AuthorityDigest: artifact.Digest{5}, VerifiedAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	// Exact pre-size field order/tags: adding an omitted field must preserve the
	// old audit plaintext and SQL audit digest, not merely equivalent JSON.
	old := struct {
		APIOutcome                                                                  *audit.APIOutcome `json:",omitempty"`
		RootID, CaptureID, ArtifactID, AttemptID, PermissionEpoch                   string
		PermissionSequence                                                          int64
		ScopeDigest, ExpectationDigest, CopiesDigest, IntentDigest, AuthorityDigest artifact.Digest
		VerifiedAt, WriteUntil, ExpiresAt, DeleteBy                                 time.Time
	}{r.APIOutcome, r.RootID, r.CaptureID, r.ArtifactID, r.AttemptID, r.PermissionEpoch, r.PermissionSequence, r.ScopeDigest, r.ExpectationDigest, r.CopiesDigest, r.IntentDigest, r.AuthorityDigest, r.VerifiedAt, r.WriteUntil, r.ExpiresAt, r.DeleteBy}
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(r)
	if !bytes.Equal(before, after) {
		t.Fatal("historical audit serialization changed")
	}
	k := keys(t)
	encrypted, err := SealContextVerification(t.Context(), k, r)
	if err != nil {
		t.Fatal(err)
	}
	size := int64(353)
	r.NativeBytes = &size
	if VerifyContextVerification(t.Context(), k, r, encrypted) == nil {
		t.Fatal("legacy audit adopted invented size")
	}
	encrypted, err = SealContextVerification(t.Context(), k, r)
	if err != nil || VerifyContextVerification(t.Context(), k, r, encrypted) != nil {
		t.Fatal("new verified length not authenticated", err)
	}
	size++
	if VerifyContextVerification(t.Context(), k, r, encrypted) == nil {
		t.Fatal("tampered native length authenticated")
	}
	size = -1
	if r.Valid() {
		t.Fatal("negative native length accepted")
	}
	size = artifact.MaxNativeBytes + 1
	if r.Valid() {
		t.Fatal("unbounded native length accepted")
	}
}
