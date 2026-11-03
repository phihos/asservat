package collector

import "time"

// ArgumentObservationBinding is distinct from packet wire-byte/cBPF authority.
// The engine/ABI definition and pre-read accounting rule are immutable accepted
// mechanism facts. A structurally valid value is not an authority issuer.
type ArgumentObservationBinding struct {
	Scope, ProgramDigest, DefinitionDigest, ExpectationDigest, AccountingRule [32]byte
	SessionID, Fence, CaptureID, ActionID, PodUID                             string
	NodeUID, BootID, CollectorPodUID, CollectorEpoch                          string
}

func (b ArgumentObservationBinding) Valid() bool {
	if b.Scope == ([32]byte{}) || b.ProgramDigest == ([32]byte{}) || b.DefinitionDigest == ([32]byte{}) || b.ExpectationDigest == ([32]byte{}) || b.AccountingRule != ArgumentObservationAccountingRule() || !validUUID(b.SessionID) || !validUUID(b.Fence) {
		return false
	}
	for _, s := range []string{b.CaptureID, b.ActionID, b.PodUID, b.NodeUID, b.BootID, b.CollectorPodUID, b.CollectorEpoch} {
		if len(s) == 0 || len(s) > 128 {
			return false
		}
	}
	return true
}

// ArgumentObservationPermit prepays one finite source once. Credits include
// attempted/faulting reads and later filtered output. They are cumulative,
// never remaining balances, and cannot renew or rearm the original session.
type ArgumentObservationPermit struct {
	Binding                                                  ArgumentObservationBinding
	StartedAt, SessionUntil, LeaseUntil, StartBy             time.Time
	Duration                                                 time.Duration
	Sequence                                                 uint64
	EventCredit, ByteCredit, EventsPerSecond, BytesPerSecond int64
	MaxProbeBytes, MaxBytesPerEvent, MaxTrackedThreads       int64
	CaptureBuffers                                           bool
}

func (p ArgumentObservationPermit) EffectiveEventsPerSecond() int64 {
	if p.MaxProbeBytes <= 0 || p.EventsPerSecond <= 0 || p.BytesPerSecond <= 0 {
		return 0
	}
	return min(p.EventsPerSecond, p.BytesPerSecond/p.MaxProbeBytes)
}

func (p ArgumentObservationPermit) ValidFinite(now time.Time) bool {
	return p.Binding.Valid() && p.Sequence == 1 && !p.StartedAt.IsZero() && !now.Before(p.StartedAt) &&
		p.Duration >= time.Second && p.Duration <= time.Minute &&
		p.SessionUntil.After(p.StartedAt) && !p.SessionUntil.After(p.StartedAt.Add(p.Duration+PacketCaptureStartWithin)) &&
		p.LeaseUntil.Equal(p.SessionUntil) && p.StartBy.After(p.StartedAt) && !p.StartBy.After(p.StartedAt.Add(PacketCaptureStartWithin)) &&
		!p.StartBy.Add(p.Duration).After(p.SessionUntil) && now.Before(p.StartBy) &&
		p.EventCredit > 0 && p.EventCredit <= 1_000_000_000 && p.ByteCredit >= p.MaxProbeBytes && p.ByteCredit <= 1<<40 &&
		p.EventsPerSecond > 0 && p.EventsPerSecond <= 100_000 && p.BytesPerSecond > 0 && p.BytesPerSecond <= 1<<30 && p.EffectiveEventsPerSecond() > 0 &&
		(p.MaxProbeBytes == 256 || p.MaxProbeBytes == 512) && p.MaxBytesPerEvent >= 1 && p.MaxBytesPerEvent <= 4096 &&
		(p.MaxProbeBytes == 256 || p.MaxBytesPerEvent >= 128) && p.MaxTrackedThreads >= 1 && p.MaxTrackedThreads <= 16384
}
