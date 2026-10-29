package collector

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestObservationAccountingRuleMatchesDocumentedCanonicalRule(t *testing.T) {
	const rule = "wire-token-bucket-v1;burst=rate;whole-frame;no-refund"
	if got := ObservationAccountingRule(); got != sha256.Sum256([]byte(rule)) {
		t.Fatalf("accounting rule changed: %x", got)
	}
}

func TestFiniteObservationPermitKeepsOriginalStartAndFullDuration(t *testing.T) {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	p := ObservationPermit{Binding: ObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte{2}, ExpectationDigest: [32]byte{3}, AccountingRule: ObservationAccountingRule(), SessionID: "11111111-1111-4111-8111-111111111111", Fence: "22222222-2222-4222-8222-222222222222", CaptureID: "capture", ActionID: "action", PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch"}, StartedAt: now, SessionUntil: now.Add(20 * time.Second), LeaseUntil: now.Add(20 * time.Second), StartBy: now.Add(5 * time.Second), Duration: 15 * time.Second, Sequence: 1, Credit: 256 << 20, BytesPerSecond: 16 << 20}
	if !p.ValidFinite(now) || !p.ValidFinite(p.StartBy.Add(-time.Nanosecond)) || p.ValidFinite(p.StartBy) {
		t.Fatal("finite start boundary was renewed")
	}
	for _, mode := range []string{"future", "bad-rule", "changed-lease", "too-long", "late-start", "no-slack", "duration", "sequence", "no-credit", "expired"} {
		t.Run(mode, func(t *testing.T) {
			x, at := p, now
			switch mode {
			case "future":
				at = now.Add(-time.Nanosecond)
			case "bad-rule":
				x.Binding.AccountingRule[0]++
			case "changed-lease":
				x.LeaseUntil = x.LeaseUntil.Add(-time.Second)
			case "too-long":
				x.SessionUntil = x.SessionUntil.Add(time.Second)
				x.LeaseUntil = x.SessionUntil
			case "late-start":
				x.StartBy = x.StartBy.Add(time.Nanosecond)
			case "no-slack":
				x.StartBy = x.StartedAt
			case "duration":
				x.Duration = 16 * time.Second
			case "sequence":
				x.Sequence = 2
			case "no-credit":
				x.Credit = 0
			case "expired":
				at = x.LeaseUntil
			}
			if x.ValidFinite(at) {
				t.Fatal("unusable finite permit accepted")
			}
		})
	}
	// Being within the lease is insufficient once the original start window has
	// closed. A later caller cannot use a still-live session to rearm acquisition.
	if !p.Lease().Valid(now.Add(6*time.Second)) || p.ValidFinite(now.Add(6*time.Second)) {
		t.Fatal("lease lifetime substituted for original start bound")
	}
}
