package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-316: the owner installation runs its operations in brackets. Every
// bracket opens and closes with one complete native proof; the operations
// inside re-read only their journals, the owner Deployment, the role journal
// and the accepted configuration. The launch always opens its own bracket.
func TestOwnerInstallationBracketBoundsRequests(t *testing.T) {
	f := newOwnerProjectionOperationPreparedFixture(t, false)
	driver, err := NewProviderOwnerInstallation(f.projection, f.roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Close)
	f.api.requests.Store(0)
	out, err := driver.Run(context.Background())
	if err != nil || !out.Complete || out.Calls != 20 || out.Finalizations != 8 || out.Inspections != 0 || out.Brackets < 2 {
		t.Fatal("bracketed installation", out, err)
	}
	if f.roles.creates != len(contracts.OwnerIdentityRolePurposes()) || projectionEffectCounts(f) != [4]int32{8, 1, 1, 1} {
		t.Fatal("fixed effect inventory changed", projectionEffectCounts(f))
	}
	// A complete native proof is 72 requests here; the operations' own reads
	// are about 25 each. Per-operation proofs took about 2450 requests.
	n := f.api.requests.Load()
	if limit := int64(out.Brackets)*2*72 + 20*27; n > limit {
		t.Fatal("bracket exceeded its proofs", n, "limit", limit, "brackets", out.Brackets)
	}
	t.Log("requests", n, "brackets", out.Brackets)
}

// A short lease ends each bracket after its first operation; the next bracket
// resumes at the recorded state and the result is the same fixed sequence.
func TestOwnerInstallationBracketResumesAcrossShortBrackets(t *testing.T) {
	f := newOwnerProjectionOperationPreparedFixture(t, false)
	driver, err := NewProviderOwnerInstallation(f.projection, f.roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Close)
	driver.reserve = time.Hour
	out, err := driver.Run(context.Background())
	// open, claim, acknowledge, verify, six projection and two launch steps
	if err != nil || !out.Complete || out.Calls != 20 || out.Finalizations != 8 || out.Brackets != 12 {
		t.Fatal("one operation per bracket", out, err)
	}
	if f.roles.creates != len(contracts.OwnerIdentityRolePurposes()) || projectionEffectCounts(f) != [4]int32{8, 1, 1, 1} {
		t.Fatal("fixed effect inventory changed", projectionEffectCounts(f))
	}
}

// An administrator removed inside a bracket is noticed by its closing proof:
// the invocation fails, the work already done keeps its exact journal
// receipts, and the launch, which needs a fresh opening proof, never runs.
func TestOwnerInstallationLostClosingProofFailsAndKeepsReceipts(t *testing.T) {
	f := newOwnerProjectionOperationPreparedFixture(t, false)
	f.roles.beforeCurrent = func() { f.fault.Store(6) } // administrator removed
	driver, err := NewProviderOwnerInstallation(f.projection, f.roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Close)
	out, err := driver.Run(context.Background())
	if err == nil || out.Complete || out.Stop != OwnerInstallationUnverified || out.Brackets != 1 {
		t.Fatal("bracket succeeded without its closing proof", out, err)
	}
	if f.launches.Load() != 0 {
		t.Fatal("launch ran after a lost closing proof")
	}
	f.fault.Store(0)
	roles, err := f.root.readOwnerIdentityOperationNative(withTimeout(t), f.root.input.LayoutDigest, true)
	if err != nil || roles.missing || roles.roles.State.Roles[0].Receipt == nil {
		t.Fatal("role receipt lost", err)
	}
	if f.roles.creates != 1 || f.journalWrites.Load() == 0 || roles.retained.resources.State.OwnerIdentity == nil {
		t.Fatal("bracket lost its completed work", f.roles.creates, f.journalWrites.Load())
	}
}

// A lost opening proof stops before any claim.
func TestOwnerInstallationLostOpeningProofClaimsNothing(t *testing.T) {
	f := newOwnerProjectionOperationPreparedFixture(t, false)
	f.fault.Store(6)
	driver, err := NewProviderOwnerInstallation(f.projection, f.roles)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(driver.Close)
	out, err := driver.Run(context.Background())
	if err == nil || out.Complete || out.Calls != 0 || f.roles.creates != 0 || f.journalWrites.Load() != 0 {
		t.Fatal("work without an opening proof", out, err)
	}
}

func withTimeout(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
