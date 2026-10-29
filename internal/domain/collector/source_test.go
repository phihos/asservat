package collector

import (
	"errors"
	"testing"
	"time"
)

func sourcePermitFixture(now time.Time) SourcePermit {
	id := "11111111-1111-4111-8111-111111111111"
	return SourcePermit{Binding: SourceBinding{RootID: id, PolicyUID: "policy", AcceptanceID: id, SourceID: id, Fence: id, ActionID: "packets", PodUID: id, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: [32]byte{3}}, StartedAt: now, HardUntil: now.Add(24 * time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1000, BytesPerSecond: 1000}
}

func TestOrdinarySourceQuietRenewalPreservesOriginalCreditAndTokens(t *testing.T) {
	now := time.Now().UTC()
	p := sourcePermitFixture(now)
	m, err := NewSourceMeter(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Charge(400, now); err != nil {
		t.Fatal(err)
	}
	next := p
	next.IssuedAt = now.Add(time.Millisecond)
	next.DispatchUntil = next.IssuedAt.Add(5 * time.Second)
	next.LeafUntil = next.IssuedAt.Add(SourceLeafLifetime)
	if err = m.Renew(next, next.IssuedAt); err != nil {
		t.Fatal(err)
	}
	if m.ObservedBytes() != 400 || m.Permit().Credit != 1000 {
		t.Fatal("renewal reset observed or prepaid credit")
	}
	if err = m.Charge(602, next.IssuedAt); !errors.Is(err, ErrObservationBudgetExhausted) {
		t.Fatal("renewal reset spend", err)
	}
	// Rate state also survives: large credit does not refill the 600-byte
	// remaining initial burst (plus one elapsed millisecond).
	next.Credit = 2000
	next.IssuedAt = next.IssuedAt.Add(time.Nanosecond)
	next.DispatchUntil = next.IssuedAt.Add(5 * time.Second)
	next.LeafUntil = next.IssuedAt.Add(SourceLeafLifetime)
	if err = m.Renew(next, next.IssuedAt); err != nil {
		t.Fatal(err)
	}
	if err = m.Charge(602, next.IssuedAt); !errors.Is(err, ErrObservationRateExceeded) {
		t.Fatal("renewal refilled tokens", err)
	}
	if err = m.Charge(600, next.IssuedAt); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinarySourceRenewalCannotRestartOrChangeScope(t *testing.T) {
	now := time.Now().UTC()
	p := sourcePermitFixture(now)
	for name, change := range map[string]func(*SourcePermit){
		"fence":                func(p *SourcePermit) { p.Binding.Fence = "22222222-2222-4222-8222-222222222222" },
		"process":              func(p *SourcePermit) { p.Binding.CollectorEpoch = "22222222-2222-4222-8222-222222222222" },
		"credit":               func(p *SourcePermit) { p.Credit-- },
		"hardend":              func(p *SourcePermit) { p.HardUntil = p.HardUntil.Add(time.Second) },
		"same-issued-conflict": func(p *SourcePermit) { p.Credit++ },
		"future":               func(p *SourcePermit) { p.IssuedAt = now.Add(time.Second) },
		"dispatch":             func(p *SourcePermit) { p.DispatchUntil = now },
		"leaf":                 func(p *SourcePermit) { p.LeafUntil = p.LeafUntil.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			m, err := NewSourceMeter(p, now)
			if err != nil {
				t.Fatal(err)
			}
			next := p
			change(&next)
			if err = m.Renew(next, now); err == nil {
				t.Fatal("accepted changed scope/cutoff")
			}
			if m.Permit() != p {
				t.Fatal("failed renewal mutated state")
			}
		})
	}
	m, _ := NewSourceMeter(p, now)
	if err := m.Renew(p, now); err != nil {
		t.Fatal("exact replay", err)
	}
	next := p
	next.IssuedAt = p.LeafUntil
	next.DispatchUntil = next.IssuedAt.Add(5 * time.Second)
	next.LeafUntil = next.IssuedAt.Add(SourceLeafLifetime)
	if err := m.Renew(next, p.LeafUntil); !errors.Is(err, ErrObservationLeaseExpired) {
		t.Fatal("resurrected expired source", err)
	}
	if _, err := NewSourceMeter(next, next.IssuedAt); err == nil {
		t.Fatal("renewal started replacement engine")
	}
}

func TestSourceBudgetReservationIsAggregateAtomicAndHeldAcrossRenewal(t *testing.T) {
	c := Ceilings{SourceLimits: SourceLimits{2, 100, 100}, RingBytes: 100, FrozenBytes: 100}
	b, err := NewBudget(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := SourceReservation{40, 40, 40}
	if err = b.ReserveSource(r); err != nil {
		t.Fatal(err)
	}
	if err = b.ReserveFrozen(70); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []SourceReservation{{61, 1, 1}, {1, 61, 1}, {1, 1, 61}, {0, 1, 1}} {
		if err = b.ReserveSource(bad); err == nil {
			t.Fatal("accepted over limit", bad)
		}
		if n, rate, burst := b.SourceUsage(); n != 1 || rate != 40 || burst != 40 || b.Usage(time.Now()).RingReserved != 40 {
			t.Fatal("partial reservation")
		}
	}
	if err = b.ReserveSource(r); err != nil {
		t.Fatal(err)
	}
	if err = b.ReserveSource(SourceReservation{1, 1, 1}); !errors.Is(err, ErrExceeded) {
		t.Fatal("source count", err)
	}
	if err = b.ReleaseSource(r); err != nil {
		t.Fatal(err)
	}
	if err = b.ReleaseSource(r); err != nil {
		t.Fatal(err)
	}
	if n, rate, burst := b.SourceUsage(); n != 0 || rate != 0 || burst != 0 || b.Usage(time.Now()).RingReserved != 0 || b.Usage(time.Now()).FrozenReserved != 70 {
		t.Fatal("release damaged independent frozen budget")
	}
	if err = b.ReleaseSource(r); err == nil {
		t.Fatal("double release")
	}
	legacy, _ := NewBudget(Ceilings{RingBytes: 100}, time.Now())
	if err = legacy.ReserveSource(r); !errors.Is(err, ErrExceeded) {
		t.Fatal("old ceiling enabled source", err)
	}
}

func TestSourceMeterUsesAcceptedRateCeilingWithoutOverflowOrFractionLoss(t *testing.T) {
	now := time.Now().UTC()
	p := sourcePermitFixture(now)
	p.BytesPerSecond = MaxInputRate
	p.Credit = 1 << 50 // no unrelated finite observation's 1 TiB cap
	m, err := NewSourceMeter(p, now)
	if err != nil {
		t.Fatal(err)
	}
	// Consume the 10 GiB burst using valid uint32 wire records.
	for _, wire := range []int64{1<<32 - 1, 1<<32 - 1, 2<<30 + 2} {
		if err = m.Charge(wire, now); err != nil {
			t.Fatal(err)
		}
	}
	if err = m.Charge(1, now); !errors.Is(err, ErrObservationRateExceeded) {
		t.Fatal("burst overflow", err)
	}
	if err = m.Charge(1<<32-1, now.Add(time.Second)); err != nil {
		t.Fatal("large-rate refill overflow", err)
	}
	p = sourcePermitFixture(now)
	p.BytesPerSecond = 3
	m, err = NewSourceMeter(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Charge(3, now); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err = m.Charge(1, now.Add(time.Duration(i)*time.Second/3+time.Nanosecond)); err != nil {
			t.Fatal("fraction lost", i, err)
		}
	}
}

func TestSourceLoweringsApplyToAllAlreadyHeldNodeResources(t *testing.T) {
	c := Ceilings{SourceLimits: SourceLimits{MaxActiveSources: 10, InputBytesPerSecond: 100, InputBurstBytes: 100}, RingBytes: 100, FrozenBytes: 100}
	b, err := NewBudget(c, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = b.ReserveSource(SourceReservation{40, 40, 40}); err != nil {
		t.Fatal(err)
	}
	for name, limits := range map[string]PolicyLimits{
		"count": {SourceLimits: SourceLimits{MaxActiveSources: 1}},
		"rate":  {SourceLimits: SourceLimits{InputBytesPerSecond: 50}},
		"burst": {SourceLimits: SourceLimits{InputBurstBytes: 50}},
		"ring":  {RingBytes: 50},
	} {
		t.Run(name, func(t *testing.T) {
			if err = b.ReserveSourceWithin(SourceReservation{20, 20, 20}, limits); !errors.Is(err, ErrExceeded) {
				t.Fatal("policy created independent local pool", err)
			}
			if n, r, burst := b.SourceUsage(); n != 1 || r != 40 || burst != 40 {
				t.Fatal("partial lowering mutation")
			}
		})
	}
	if b.Ceilings() != c {
		t.Fatal("policy permanently lowered configured ceilings")
	}
	if err = b.ReserveFrozen(40); err != nil {
		t.Fatal(err)
	}
	if err = b.ReserveFrozenWithin(20, PolicyLimits{FrozenBytes: 50}); !errors.Is(err, ErrExceeded) {
		t.Fatal("snapshot ignored aggregate lowering", err)
	}
	if err = b.ReserveFrozenWithin(20, PolicyLimits{FrozenBytes: 200}); err != nil {
		t.Fatal(err)
	}
	if b.Ceilings() != c || b.Usage(time.Now()).FrozenReserved != 60 {
		t.Fatal("lowering grew ceiling or refunded existing copy")
	}
}
