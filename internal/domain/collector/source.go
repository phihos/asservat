package collector

import (
	"asservat.local/asservat/internal/domain/planning"
	"time"
)

// SourceBinding is the immutable purpose-separated identity of one ordinary
// sanitized ongoing source. It deliberately has no capture or incident ID.
// These values need committed producer authority and authenticated delivery;
// structural validity does not confer either.
type SourceBinding struct {
	AudienceDigest                                                     [32]byte `json:",omitzero"`
	RootID, PolicyUID, AcceptanceID, SourceID, Fence                   string
	ActionID, PodUID, NodeUID, BootID, CollectorPodUID, CollectorEpoch string
	Scope, ExpectationDigest, ProgramDigest, ResourceDigest            [32]byte
}

func (b SourceBinding) Valid() bool {
	for _, id := range []string{b.RootID, b.AcceptanceID, b.SourceID, b.Fence, b.PodUID, b.NodeUID, b.BootID, b.CollectorPodUID, b.CollectorEpoch} {
		if !validUUID(id) {
			return false
		}
	}
	return len(b.PolicyUID) > 0 && len(b.PolicyUID) <= 128 && len(b.ActionID) > 0 && len(b.ActionID) <= 128 &&
		b.Scope != ([32]byte{}) && b.ExpectationDigest != ([32]byte{}) && b.ResourceDigest != ([32]byte{})
}

const SourceLeafLifetime = 30 * time.Second
const SourceStatusLimit = MaxActiveSources + MaxQueuedWork

// SourceRingLimits is the portable resolved ring plan. Its physical segment
// allocation includes framing; frozen copies are a separate global budget.
type SourceRingLimits struct {
	MaxAge                                 time.Duration
	MaxBytes, SegmentBytes, MaxFrozenBytes int64
	MaxSegments, MaxConcurrentSnapshots    int
}

func (r SourceRingLimits) Valid() bool {
	return r.MaxAge > 0 && r.MaxAge <= time.Hour && r.MaxBytes > 0 && r.MaxBytes <= 256<<20 &&
		r.SegmentBytes > 32 && r.SegmentBytes <= 64<<20 && r.MaxSegments >= 2 && r.MaxSegments <= 64 &&
		int64(r.MaxSegments) <= r.MaxBytes/r.SegmentBytes && r.MaxConcurrentSnapshots >= 1 && r.MaxConcurrentSnapshots <= 4 && r.MaxFrozenBytes > 0 && r.MaxFrozenBytes <= 256<<20
}

// PacketSource is purpose-specific authenticated node work, not collection or
// disclosure authority. The exact same resolved plan accompanies quiet renewals.
type PacketSource struct {
	Permit    SourcePermit
	Program   []planning.BPFInstruction
	Ring      SourceRingLimits
	Resources SourceResources
}

// SourceResources binds the exact protected resource policy and lowerings,
// separately from accepted collection intent and configured local ceilings.
type SourceResources struct {
	PolicyUID string
	Node      PolicyLimits
	Workload  SourceLimits
}

func (r SourceResources) Valid() bool {
	return len(r.PolicyUID) > 0 && len(r.PolicyUID) <= 128 && r.Node.Valid() && r.Workload.Valid()
}

// SourceStatus is bounded, content-free cumulative local accounting. It is
// not a permit or a proof that an unknown input loss observed zero bytes.
type SourceStatus struct {
	SourceStoppedAt               time.Time `json:",omitzero"`
	SnapshotUntil                 time.Time `json:",omitzero"`
	SourceID, Fence               string
	IssuedAt, LeafUntil           time.Time
	Credit, ObservedBytes         int64
	Closed, Stopped, InputUnknown bool
}

func (s SourceStatus) Valid(observedAt time.Time) bool {
	// The source-set timestamp precedes enumeration: a concurrent natural
	// stop can have a later original timestamp without renewing the set proof.
	if !s.SourceStoppedAt.IsZero() && !s.Stopped || !s.SnapshotUntil.IsZero() && s.SnapshotUntil.After(s.LeafUntil) {
		return false
	}
	return validUUID(s.SourceID) && validUUID(s.Fence) && !s.IssuedAt.IsZero() && !s.IssuedAt.After(observedAt) && s.LeafUntil.After(s.IssuedAt) && !s.LeafUntil.After(s.IssuedAt.Add(SourceLeafLifetime)) && s.Credit > 0 && s.ObservedBytes >= 0 && s.ObservedBytes <= s.Credit
}

func (s PacketSource) Valid() bool {
	return s.Permit.Valid(s.Permit.IssuedAt) && s.Ring.Valid() && s.Resources.Valid() && len(s.Program) <= planning.MaxFilterInstructions && (len(s.Program) == 0) == (s.Permit.Binding.ProgramDigest == [32]byte{})
}

// SourcePermit separates the original hard session/start bounds, each new
// at-most-five-second dispatch operation, and its absolute active leaf. Quiet
// renewal changes IssuedAt, DispatchUntil and LeafUntil, not prepaid Credit.
// No receipt or receiver timestamp can restart these intervals.
type SourcePermit struct {
	Binding                            SourceBinding
	StartedAt, HardUntil, StartBy      time.Time
	IssuedAt, DispatchUntil, LeafUntil time.Time
	Credit, BytesPerSecond             int64
}

func (p SourcePermit) Valid(now time.Time) bool {
	return p.Binding.Valid() && !p.StartedAt.IsZero() && !p.IssuedAt.Before(p.StartedAt) && !now.Before(p.IssuedAt) &&
		p.HardUntil.After(p.StartedAt) &&
		p.StartBy.After(p.StartedAt) && !p.StartBy.After(p.StartedAt.Add(5*time.Second)) && !p.StartBy.After(p.HardUntil) &&
		p.DispatchUntil.After(p.IssuedAt) && !p.DispatchUntil.After(p.IssuedAt.Add(5*time.Second)) &&
		!p.DispatchUntil.After(p.LeafUntil) && now.Before(p.LeafUntil) && !p.LeafUntil.After(p.IssuedAt.Add(SourceLeafLifetime)) &&
		!p.LeafUntil.After(p.HardUntil) && p.Credit > 0 && p.BytesPerSecond > 0 && p.BytesPerSecond <= MaxInputRate
}

func (p SourcePermit) Dispatchable(now time.Time) bool {
	return p.Valid(now) && now.Before(p.DispatchUntil)
}
func (p SourcePermit) Startable(now time.Time) bool {
	return p.Dispatchable(now) && p.IssuedAt.Equal(p.StartedAt) && now.Before(p.StartBy)
}

// SourceMeter enforces the same wire-token rule without changing the distinct
// finite ObservationPermit contract. Whole bytes plus a fractional remainder
// support the existing administrator MaxInputRate without int64 byte-nanosecond
// overflow or a new lower source-rate ceiling.
// Its owner serializes Charge and Renew and stops the engine on any refusal.
type SourceMeter struct {
	permit                     SourcePermit
	observed, tokens, fraction int64
	last                       time.Time
}

func NewSourceMeter(p SourcePermit, now time.Time) (*SourceMeter, error) {
	if !p.Startable(now) {
		return nil, ErrObservationInvalid
	}
	return &SourceMeter{permit: p, last: now, tokens: p.BytesPerSecond}, nil
}
func (m *SourceMeter) Permit() SourcePermit { return m.permit }
func (m *SourceMeter) ObservedBytes() int64 { return m.observed }
func (m *SourceMeter) Charge(wire int64, now time.Time) error {
	if wire <= 0 || wire > 1<<32-1 || now.Before(m.last) {
		return ErrObservationInvalid
	}
	if !now.Before(m.permit.LeafUntil) || !now.Before(m.permit.HardUntil) {
		return ErrObservationLeaseExpired
	}
	if wire > m.permit.Credit-m.observed {
		return ErrObservationBudgetExhausted
	}
	// Existing MaxInputRate (10 GiB/s) * capped 1e9 nanoseconds plus
	// fraction fits uint64, though it can exceed MaxInt64.
	refill := uint64(min(now.Sub(m.last), time.Second))*uint64(m.permit.BytesPerSecond) + uint64(m.fraction)
	add, fraction := refill/uint64(time.Second), refill%uint64(time.Second)
	tokens := min(m.permit.BytesPerSecond, m.tokens+int64(add))
	if tokens == m.permit.BytesPerSecond {
		fraction = 0
	}
	if wire > tokens {
		return ErrObservationRateExceeded
	}
	m.tokens, m.fraction, m.last, m.observed = tokens-wire, int64(fraction), now, m.observed+wire
	return nil
}

func (m *SourceMeter) Renew(next SourcePermit, now time.Time) error {
	old := m.permit
	if !now.Before(old.LeafUntil) {
		return ErrObservationLeaseExpired
	}
	if !next.Dispatchable(now) || next.Binding != old.Binding || !next.StartedAt.Equal(old.StartedAt) ||
		!next.HardUntil.Equal(old.HardUntil) || !next.StartBy.Equal(old.StartBy) || next.BytesPerSecond != old.BytesPerSecond ||
		next.Credit < old.Credit || next.IssuedAt.Before(old.IssuedAt) || next.LeafUntil.Before(old.LeafUntil) {
		return ErrObservationInvalid
	}
	if next.IssuedAt.Equal(old.IssuedAt) && (next.Credit != old.Credit || !next.DispatchUntil.Equal(old.DispatchUntil) || !next.LeafUntil.Equal(old.LeafUntil)) {
		return ErrObservationInvalid
	}
	// Preserve observed bytes, refilled-at and tokens. Absolute issuance time
	// orders quiet grants without requiring a new durable counter per tick.
	m.permit = next
	return nil
}
