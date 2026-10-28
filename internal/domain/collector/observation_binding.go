package collector

import "time"

// ObservationRule pins wire-byte token accounting, including its one-second
// initial burst. The canonical rule is
// wire-token-bucket-v1;burst=rate;whole-frame;no-refund.
// This is local enforcement, never an authority issuer.
func ObservationAccountingRule() [32]byte {
	return [32]byte{0x4d, 0x3f, 0x2e, 0xea, 0x2e, 0xd2, 0x80, 0xbd, 0x70, 0x17, 0xea, 0x23, 0x98, 0xa4, 0xcd, 0xe1, 0x8d, 0x94, 0xda, 0xac, 0xbc, 0xc4, 0xc8, 0x74, 0x1a, 0x98, 0xd5, 0x2c, 0x56, 0x69, 0x74, 0x53}
}

// ObservationBinding must eventually come from committed authority and an exact
// authenticated node-channel resolution. Scope binds original root, policy,
// acceptance, grant, source/action plan and program digests, not current aliases.
// A local value alone cannot establish global ownership or prevent another process
// from constructing a second meter. The unwired issuer/channel must do that.
type ObservationBinding struct {
	Scope                                            [32]byte
	AccountingRule                                   [32]byte
	SessionID, Fence, CaptureID, ActionID, PodUID    string
	NodeUID, BootID, CollectorPodUID, CollectorEpoch string
}

func (b ObservationBinding) Valid() bool {
	if b.Scope == ([32]byte{}) || b.AccountingRule != ObservationAccountingRule() {
		return false
	}
	for _, s := range []string{b.SessionID, b.Fence, b.CaptureID, b.ActionID, b.PodUID, b.NodeUID, b.BootID, b.CollectorPodUID, b.CollectorEpoch} {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
	}
	return true
}

// ObservationPermit has an immutable original session and rate. Credit is a
// cumulative reservation ceiling, never remaining balance or measured input.
type ObservationPermit struct {
	Binding                             ObservationBinding
	StartedAt, SessionUntil, LeaseUntil time.Time
	Sequence                            uint64
	Credit, BytesPerSecond              int64
}

func (p ObservationPermit) Lease() ObservationLease {
	return ObservationLease{SessionID: p.Binding.SessionID, Fence: p.Binding.Fence, Sequence: p.Sequence, StartedAt: p.StartedAt, SessionUntil: p.SessionUntil, LeaseUntil: p.LeaseUntil, Credit: p.Credit, MaxBytesPerSecond: p.BytesPerSecond}
}
