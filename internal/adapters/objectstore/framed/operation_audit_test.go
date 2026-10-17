package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

func TestOperationAuditExactRecordsAndProviderCallCount(t *testing.T) {
	ctx := context.Background()
	k := &countingKeys{testKeys: keys(t)}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in := audit.OperationIntent{ID: "00000000-0000-4000-8000-000000000001", RootID: "00000000-0000-4000-8000-000000000002", TraceID: "00000000-0000-4000-8000-000000000001", Name: "get_case", InputFormat: "context-input/v1", MACVersion: "v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	out := audit.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, OutputBytes: 24 << 10, MetadataUntil: in.RequestUntil, RecordedAt: now}
	start := time.Now()
	a, e := SealOperationIntent(ctx, k, in)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyOperationIntent(ctx, k, in, a); e != nil {
		t.Fatal(e)
	}
	b, e := SealOperationOutcome(ctx, k, out)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyOperationOutcome(ctx, k, out, b); e != nil {
		t.Fatal(e)
	}
	t.Logf("local Tink audit only: wraps=%d unwraps=%d max_wrapped_key_bytes=%d intent_cipher_bytes=%d outcome_cipher_bytes=%d elapsed=%s; no network provider latency measured", k.wraps, k.unwraps, k.maxKeyBytes, len(a), len(b), time.Since(start))
	if k.wraps != 2 || k.unwraps != 2 || k.maxKeyBytes > 4096 {
		t.Fatal("audit call count differs from the separate three-wrap artifact contract")
	}
	changed := in
	changed.InputDigest[0]++
	if VerifyOperationIntent(ctx, k, changed, a) == nil {
		t.Fatal("changed argument digest verified")
	}
	changed = in
	changed.ID = "00000000-0000-4000-8000-000000000004"
	if VerifyOperationIntent(ctx, k, changed, a) == nil {
		t.Fatal("cross-request transplant")
	}
	changedOut := out
	changedOut.OutputBytes++
	if VerifyOperationOutcome(ctx, k, changedOut, b) == nil {
		t.Fatal("changed output verified")
	}
	b[len(b)/2] ^= 1
	if VerifyOperationOutcome(ctx, k, out, b) == nil {
		t.Fatal("corrupt outcome verified")
	}
}
