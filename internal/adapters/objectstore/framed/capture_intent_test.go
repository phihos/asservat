package framed

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func TestCaptureAuditAuthenticatesPurposeAndFrozenRecord(t *testing.T) {
	ctx := context.Background()
	k := keys(t)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	id := testBinding.ClusterID
	r := audit.CaptureIntent{RootID: id, CaptureID: testBinding.ArtifactID, CaseID: id, OccurrenceID: id, ArtifactID: testBinding.ArtifactID, AttemptID: testBinding.AttemptID, Actor: identity.Principal{Issuer: "https://id.example.test", Subject: "synthetic-developer", ClientID: "browser", Kind: identity.Human}, Target: authorization.Target{ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod"}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: id, PermissionSequence: 1, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: [32]byte{4}}, CreatedAt: now, Deadline: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(time.Hour + 5*time.Minute), ReservedBytes: 2 << 20}
	b, err := SealCaptureIntent(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyCaptureIntent(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(r.Actor.Subject)) {
		t.Fatal("plaintext identity in envelope")
	}
	changed := r
	changed.ExpectationDigest[0]++
	if VerifyCaptureIntent(ctx, k, changed, b) == nil {
		t.Fatal("changed audience/retention expectation authenticated")
	}
	changed = r
	changed.RootID = testBinding.AttemptID
	if VerifyCaptureIntent(ctx, k, changed, b) == nil {
		t.Fatal("wrong root authenticated")
	}
	var envelope authorityEnvelope
	if json.Unmarshal(b, &envelope) != nil {
		t.Fatal("bad fixture")
	}
	envelope.Format = auditFormat
	other, _ := json.Marshal(envelope)
	if VerifyCaptureIntent(ctx, k, r, other) == nil {
		t.Fatal("authority purpose accepted")
	}
	// Even changing both the visible format and verifier cannot transplant keys
	// between purposes: format/root/event/plain digest are authenticated AAD.
	if verifyControlAudit(ctx, k, auditFormat, r.RootID, r.CaptureID, r, other, 64<<10) == nil {
		t.Fatal("cross-purpose key substitution")
	}
	envelope.Format = captureIntentFormat
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
	other, _ = json.Marshal(envelope)
	if VerifyCaptureIntent(ctx, k, r, other) == nil {
		t.Fatal("corruption accepted")
	}
	duplicate := append([]byte(`{"format":"asservat-capture-intent-audit/v1",`), b[1:]...)
	if VerifyCaptureIntent(ctx, k, r, duplicate) == nil {
		t.Fatal("duplicate keys accepted")
	}
	k.fail = true
	if _, err = SealCaptureIntent(ctx, k, r); err == nil {
		t.Fatal("key failure fell back to plaintext")
	}
}
