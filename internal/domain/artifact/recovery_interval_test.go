package artifact

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// ADR-311: one recovery observation serves an operation for at most the
// recheck interval; it is never valid at or after its own FreshUntil.
func TestRecoveryProofAdmitsOnlyTheRecheckInterval(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	p := RecoveryProof{InstallationID: "11111111-1111-4111-8111-111111111111", IssuerEpoch: "22222222-2222-4222-8222-222222222222", Revision: identity.Revision{UID: "trust", Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(identity.AuthorityRecheckInterval)}
	if !p.Valid(now.Add(identity.AuthorityRecheckInterval - time.Microsecond)) {
		t.Fatal("recheck-interval recovery observation rejected before its end")
	}
	if p.Valid(p.FreshUntil) {
		t.Fatal("recovery observation valid at its own end")
	}
	p.FreshUntil = now.Add(identity.AuthorityRecheckInterval + time.Microsecond)
	if p.Valid(now) {
		t.Fatal("recovery observation longer than the recheck interval accepted")
	}
}
