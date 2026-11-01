package collector

import (
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func defaults() Ceilings {
	return Ceilings{SourceLimits{}, DefaultNodeRingBytes, DefaultNodeFrozen, DefaultNodeUploadRate, DefaultNodeBurst}
}

func TestCeilingsValidAndIntersect(t *testing.T) {
	if !defaults().Valid() || !(Ceilings{}).Valid() {
		t.Fatal("defaults and all-zero ceilings are valid")
	}
	for _, c := range []Ceilings{{RingBytes: -1}, {RingBytes: MaxNodeRingBytes + 1}, {FrozenBytes: MaxNodeFrozenBytes + 1}, {UploadBytesPerSecond: 1}, {UploadBurstBytes: 1}, {UploadBytesPerSecond: MaxNodeUploadRate + 1, UploadBurstBytes: 1}} {
		if c.Valid() {
			t.Fatalf("%+v accepted", c)
		}
	}
	got := defaults().Intersect(PolicyLimits{RingBytes: 64 << 20, FrozenBytes: 1 << 40, UploadBurstBytes: 1 << 20})
	if got != (Ceilings{SourceLimits{}, 64 << 20, DefaultNodeFrozen, DefaultNodeUploadRate, 1 << 20}) {
		t.Fatalf("intersection %+v", got)
	}
	if defaults().Intersect(PolicyLimits{}) != defaults() {
		t.Fatal("absent policy limits must not change the collector ceiling")
	}
}

func TestRingAndFrozenReservationsNeverExceedCeilings(t *testing.T) {
	b, err := NewBudget(Ceilings{RingBytes: 256 << 20, FrozenBytes: 64 << 20}, t0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		if err := b.ReserveRing(16 << 20); err != nil {
			t.Fatalf("ring %d: %v", i, err)
		}
	}
	if err := b.ReserveRing(1); !errors.Is(err, ErrExceeded) {
		t.Fatalf("17th ring byte: %v", err)
	}
	if err := b.ReserveFrozen(64<<20 + 1); !errors.Is(err, ErrExceeded) || b.Usage(t0).FrozenReserved != 0 {
		t.Fatal("an oversized frozen reservation must fail without partial effect")
	}
	if b.ReserveFrozen(64<<20) != nil || b.ReleaseFrozen(64<<20+1) == nil || b.ReleaseFrozen(64<<20) != nil || b.ReleaseFrozen(1) == nil {
		t.Fatal("frozen release must match held bytes")
	}
	if b.ReleaseRing(16<<20) != nil || b.ReserveRing(16<<20) != nil || b.ReserveRing(0) == nil || b.ReserveRing(-1) == nil {
		t.Fatal("ring release/reserve")
	}
	u := b.Usage(t0)
	if u.RingReserved != 256<<20 || u.FrozenReserved != 0 || u.Ceilings.RingBytes != 256<<20 {
		t.Fatalf("usage %+v", u)
	}
	zero, _ := NewBudget(Ceilings{}, t0)
	if !errors.Is(zero.ReserveRing(1), ErrExceeded) || !errors.Is(zero.ReserveFrozen(1), ErrExceeded) {
		t.Fatal("zero ceilings admit nothing")
	}
	if _, err := zero.TakeUpload(t0, 1); !errors.Is(err, ErrExceeded) {
		t.Fatal("zero upload admits nothing")
	}
}

func TestUploadTokenBucket(t *testing.T) {
	b, err := NewBudget(Ceilings{UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if w, err := b.TakeUpload(t0, 64<<20); w != 0 || err != nil {
		t.Fatalf("full burst at start: %v %v", w, err)
	}
	w, err := b.TakeUpload(t0, 8<<20)
	if err != nil || w != 250*time.Millisecond {
		t.Fatalf("wait for 8 MiB at 32 MiB/s: %v %v", w, err)
	}
	if b.Usage(t0).UploadAvailable != 0 {
		t.Fatal("a refused take must not consume")
	}
	if w, err := b.TakeUpload(t0.Add(250*time.Millisecond), 8<<20); w != 0 || err != nil {
		t.Fatalf("after refill: %v %v", w, err)
	}
	// A clock step backwards refills nothing; a long gap refills only to the burst.
	if b.Usage(t0).UploadAvailable != 0 {
		t.Fatal("backwards clock refilled")
	}
	if got := b.Usage(t0.Add(time.Hour)).UploadAvailable; got != 64<<20 {
		t.Fatalf("refill capped at burst: %d", got)
	}
	if _, err := b.TakeUpload(t0.Add(time.Hour), 64<<20+1); !errors.Is(err, ErrExceeded) {
		t.Fatal("more than the burst can never be taken")
	}
	if _, err := b.TakeUpload(t0, 0); err == nil {
		t.Fatal("zero take accepted")
	}
	if _, err := NewBudget(Ceilings{UploadBytesPerSecond: 1}, t0); err == nil {
		t.Fatal("rate without burst accepted")
	}
	// Large rate and gap must not overflow.
	big, _ := NewBudget(Ceilings{UploadBytesPerSecond: MaxNodeUploadRate, UploadBurstBytes: MaxNodeUploadBurst}, t0)
	big.TakeUpload(t0, MaxNodeUploadBurst)
	if got := big.Usage(t0.Add(1000 * time.Hour)).UploadAvailable; got != MaxNodeUploadBurst {
		t.Fatalf("overflow guard: %d", got)
	}
}

func TestOngoingSourceCeilingsAreIndependentAndOnlyLowered(t *testing.T) {
	c := defaults()
	if c.SourceLimits.Enabled() {
		t.Fatal("legacy finite budgets must not enable ongoing sources")
	}
	c.SourceLimits = SourceLimits{DefaultActiveSources, DefaultInputRate, DefaultInputBurst}
	if !c.Valid() || !c.SourceLimits.Enabled() {
		t.Fatal("development ceilings rejected")
	}
	p := PolicyLimits{SourceLimits: SourceLimits{4, 2 << 20, 1 << 20}}
	got := c.Intersect(p)
	if got.SourceLimits != p.SourceLimits || got.RingBytes != c.RingBytes || got.UploadBytesPerSecond != c.UploadBytesPerSecond {
		t.Fatal("ongoing limits changed finite quantities", got)
	}
	for i := 0; i < 20; i++ {
		got = got.Intersect(p)
	}
	if got.SourceLimits != p.SourceLimits {
		t.Fatal("replicas multiplied limits")
	}
	if c.Intersect(PolicyLimits{SourceLimits: SourceLimits{32, 32 << 20, 32 << 20}}) != c {
		t.Fatal("policy raised collector ceilings")
	}
	if (Ceilings{}).Intersect(p).SourceLimits.Enabled() {
		t.Fatal("policy enabled zero collector ceilings")
	}
	for _, s := range []SourceLimits{{-1, 1, 1}, {MaxActiveSources + 1, 1, 1}, {1, -1, 1}, {1, MaxInputRate + 1, 1}, {1, 1, MaxInputBurst + 1}} {
		if s.Valid() {
			t.Fatal("invalid source limits", s)
		}
	}
}

func TestPartialOngoingNodeCeilingsRefuseWhileOptionalPolicyCanLowerOneField(t *testing.T) {
	for _, s := range []SourceLimits{{MaxActiveSources: 1}, {InputBytesPerSecond: 1, InputBurstBytes: 1}} {
		if (Ceilings{SourceLimits: s}).Valid() {
			t.Fatal("partial node caps accepted", s)
		}
	}
	c := Ceilings{SourceLimits: SourceLimits{16, 16 << 20, 16 << 20}}
	if !c.Intersect(PolicyLimits{SourceLimits: SourceLimits{MaxActiveSources: 2}}).Valid() {
		t.Fatal("optional count-only policy invalidated complete node ceilings")
	}
}
