package framed

import (
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type captureWideKeys struct {
	base     *testKeys
	original artifact.SealedKey
}

func (k *captureWideKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	original, e := k.base.Seal(ctx, b, ad)
	if e != nil {
		return original, e
	}
	k.original = original
	return artifact.SealedKey{Reference: strings.Repeat("\\", 256), Ciphertext: strings.Repeat("\\", 8192)}, nil
}
func (k *captureWideKeys) Open(ctx context.Context, v artifact.SealedKey, ad []byte) ([]byte, error) {
	if len(v.Reference) != 256 || len(v.Ciphertext) != 8192 {
		return nil, artifact.ErrIntegrity
	}
	return k.base.Open(ctx, k.original, ad)
}
func captureFramedIntent(t *testing.T) value.OperationIntent {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	id := "00000000-0000-4000-8000-000000000001"
	actor := identity.Principal{Issuer: strings.Repeat("\\", 2048), Subject: strings.Repeat("\\", 256), ClientID: strings.Repeat("\\", 256), Kind: identity.Human}
	c := value.CaptureIntent{RootID: id, CaptureID: id, CaseID: id, OccurrenceID: id, ArtifactID: id, AttemptID: id, Actor: actor, Target: authorization.Target{ClusterID: id, NamespaceUID: strings.Repeat("\\", 64), WorkloadUID: strings.Repeat("\\", 64), PodUID: strings.Repeat("\\", 64)}, ScopeDigest: artifact.Digest{1}, SubmissionDigest: artifact.Digest{2}, ExpectationDigest: artifact.Digest{3}, PermissionEpoch: id, PermissionSequence: 1<<63 - 1, IdentityRevision: identity.Revision{UID: strings.Repeat("\\", 64), Generation: 2147483647, Digest: artifact.Digest{4}}, CreatedAt: n, Deadline: n.Add(30 * time.Second), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour), ReservedBytes: (16 << 20) - 1}
	p := value.OperationLifecyclePolicy{RootID: id, Lane: "capture", InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1 << 60, MetadataSlots: 1, BackupReservedBytes: 1<<63 - 1, WALReservedBytes: 1<<63 - 1, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), MaxPurgeLeases: 32, History: &value.OperationHistoryQualification{ID: id, Digest: artifact.Digest{3}, Layout: value.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 16 << 20, MaximumTransitionWALBytes: 64 << 20, BackupCopies: 64, WALCopies: 64}}
	in := value.OperationIntent{ID: id, RootID: id, TraceID: id, Name: value.CaptureOperationName, InputFormat: value.CaptureOperationInputFormat, MACVersion: strings.Repeat("\\", 64), AccountVersion: strings.Repeat("\\", 64), Actor: actor, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour), Capture: &c}
	for i := range c.ScopeDigest {
		c.ScopeDigest[i] = 255
		c.SubmissionDigest[i] = 255
		c.ExpectationDigest[i] = 255
		c.IdentityRevision.Digest[i] = 255
		in.PrincipalDigest[i] = 255
		in.InputDigest[i] = 255
		p.History.Digest[i] = 255
		p.PolicyDigest[i] = 255
		p.BackupProfileDigest[i] = 255
	}
	bound, e := app.BindOperationLifecycle(in, p)
	if e != nil {
		t.Fatal(e)
	}
	return bound
}
func TestCapturePrivateFormatFitsMaxTextAndWrappingEnvelope(t *testing.T) {
	in := captureFramedIntent(t)
	ctx := context.Background()
	k := &captureWideKeys{base: keys(t)}
	b, e := SealOperationIntent(ctx, k, in)
	if e != nil || len(b) > value.OperationCipherLimit {
		t.Fatal("bounded intent exceeds prepaid object", len(b), e)
	}
	if e = VerifyOperationIntent(ctx, k, in, b); e != nil {
		t.Fatal(e)
	}
	var envelope authorityEnvelope
	if json.Unmarshal(b, &envelope) != nil || envelope.Format != "asservat-capture-intent/v1" {
		t.Fatal("private record reused old format")
	}
	copied := append([]byte(nil), b...)
	envelope.Format = "asservat-operation-intent/v2"
	wrong, _ := json.Marshal(envelope)
	if VerifyOperationIntent(ctx, k, in, wrong) == nil {
		t.Fatal("old format promoted into capture protocol")
	}
	out := value.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", CaptureIDs: []string{in.ID}, OutputDigest: artifact.Digest{1}, RecordedAt: in.CreatedAt, MetadataUntil: in.RequestUntil}
	b, e = SealOperationOutcome(ctx, k, out)
	if e != nil || len(b) > value.OperationCipherLimit {
		t.Fatal("bounded outcome exceeds prepaid object", len(b), e)
	}
	if e = VerifyOperationOutcome(ctx, k, out, b); e != nil {
		t.Fatal(e)
	}
	t.Logf("actual Tink ciphertext under maximum opaque wrapping text: intent=%d outcome=%d prepaid=%d bytes", len(copied), len(b), value.OperationCipherLimit)
	if bytes.Equal(copied, b) {
		t.Fatal("phase format not separated")
	}
	in.Actor.Issuer += "x"
	c := *in.Capture
	c.Actor = in.Actor
	in.Capture = &c
	if _, e = SealOperationIntent(ctx, k, in); e == nil {
		t.Fatal("oversize actor encrypted")
	}
}
func TestCapturePrivateEnvelopeRejectsControlExpansion(t *testing.T) {
	_, e := captureEnvelope(authorityEnvelope{Format: "asservat-capture-intent/v1", Key: artifact.SealedKey{Reference: "r", Ciphertext: strings.Repeat("\x00", 8192)}, Ciphertext: make([]byte, 24<<10)})
	if e == nil {
		t.Fatal("unqualified control-byte key envelope exceeded fixed backing")
	}
}
