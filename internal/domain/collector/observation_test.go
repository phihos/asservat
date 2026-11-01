package collector

import (
	"errors"
	"testing"
	"time"
)

func observationFixture(now time.Time) ObservationLease {
	return ObservationLease{SessionID: "00000000-0000-4000-8000-000000000001", Fence: "00000000-0000-4000-8000-000000000002", Sequence: 1, StartedAt: now, SessionUntil: now.Add(time.Minute), LeaseUntil: now.Add(20 * time.Second), Credit: 1000, MaxBytesPerSecond: 10000}
}

func TestObservationChargesBeforeDiscardedPredicate(t *testing.T) {
	now := time.Now()
	m, err := NewObservationMeter(observationFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	// Mirrors the callback boundary: admission/charge precedes the predicate.
	// The predicate discards everything, so retained bytes remain zero.
	predicate := func() { called++ }
	for n := 0; n < 10; n++ {
		if err := m.Charge(100, now); err != nil {
			t.Fatal(err)
		}
		predicate()
	}
	if m.ObservedBytes() != 1000 || called != 10 {
		t.Fatal("discarded input escaped accounting")
	}
	if err := m.Charge(1, now); !errors.Is(err, ErrObservationBudgetExhausted) {
		t.Fatal("extra byte processed", err)
	}
	if m.ObservedBytes() != 1000 {
		t.Fatal("failed charge mutated actual observed count")
	}
}

func TestObservationRenewalPreservesOriginalSessionAndCredit(t *testing.T) {
	now := time.Now()
	l := observationFixture(now)
	m, err := NewObservationMeter(l, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Charge(100, now); err != nil {
		t.Fatal(err)
	}
	next := l
	next.Sequence++
	next.LeaseUntil = now.Add(30 * time.Second)
	// Parent has zero unallocated bytes; renew authority with existing credit.
	if err := m.Renew(next, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Renew(next, now.Add(2*time.Second)); err != nil {
		t.Fatal("lost-reply replay", err)
	}
	for name, change := range map[string]func(*ObservationLease){
		"new session":                func(l *ObservationLease) { l.SessionID = l.Fence },
		"new fence":                  func(l *ObservationLease) { l.Fence = l.SessionID },
		"restart time":               func(l *ObservationLease) { l.StartedAt = l.StartedAt.Add(time.Second) },
		"extend original end":        func(l *ObservationLease) { l.SessionUntil = l.SessionUntil.Add(time.Second) },
		"decrease cumulative credit": func(l *ObservationLease) { l.Credit-- },
		"change same sequence":       func(l *ObservationLease) { l.Credit++ },
		"skip sequence":              func(l *ObservationLease) { l.Sequence += 2 },
		"raise reviewed rate":        func(l *ObservationLease) { l.MaxBytesPerSecond++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := next
			change(&bad)
			if err := m.Renew(bad, now.Add(3*time.Second)); err == nil {
				t.Fatal("invalid renewal accepted")
			}
		})
	}
	if m.ObservedBytes() != 100 {
		t.Fatal("renewal refilled actual counter")
	}
	next.Sequence++
	next.Credit = 2000
	next.LeaseUntil = now.Add(40 * time.Second)
	if err := m.Renew(next, now.Add(4*time.Second)); err != nil {
		t.Fatal("cumulative credit extension", err)
	}
	if err := m.Charge(1900, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Charge(1, now.Add(4*time.Second)); !errors.Is(err, ErrObservationBudgetExhausted) {
		t.Fatal(err)
	}
}

func TestObservationLeaseAndRateStop(t *testing.T) {
	now := time.Now()
	l := observationFixture(now)
	l.Credit = 10000
	l.MaxBytesPerSecond = 1000
	m, _ := NewObservationMeter(l, now)
	if err := m.Charge(1000, now); err != nil {
		t.Fatal(err)
	}
	if err := m.Charge(1, now); !errors.Is(err, ErrObservationRateExceeded) {
		t.Fatal("rate ceiling", err)
	}
	m, _ = NewObservationMeter(l, now)
	if err := m.Charge(1000, now); err != nil {
		t.Fatal(err)
	}
	if err := m.Charge(1000, now.Add(time.Second)); err != nil {
		t.Fatal("rate did not replenish", err)
	}
	if err := m.Charge(1, l.LeaseUntil); !errors.Is(err, ErrObservationLeaseExpired) {
		t.Fatal("lease deadline bypass", err)
	}
	next := l
	next.Sequence++
	next.LeaseUntil = l.SessionUntil
	if err := m.Renew(next, l.LeaseUntil); err == nil {
		t.Fatal("expired session revived")
	}
}

func BenchmarkObservationMeterCharge(b *testing.B) {
	now := time.Now()
	l := observationFixture(now)
	l.Credit = 1 << 40
	l.MaxBytesPerSecond = 1 << 30
	m, _ := NewObservationMeter(l, now)
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		// One synthetic frame every millisecond keeps the configured rate honest.
		at := now.Add(time.Duration(n%1000) * time.Millisecond)
		if n%1000 == 0 {
			m, _ = NewObservationMeter(l, now)
		}
		if err := m.Charge(1500, at); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObservationMeterWithClock(b *testing.B) {
	now := time.Now()
	l := observationFixture(now)
	l.Credit = 1 << 40
	l.MaxBytesPerSecond = 1 << 30
	m, _ := NewObservationMeter(l, now)
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		at := time.Now()
		if n%1000 == 0 {
			l.StartedAt = at
			l.SessionUntil = at.Add(time.Minute)
			l.LeaseUntil = at.Add(20 * time.Second)
			m, _ = NewObservationMeter(l, at)
		}
		if err := m.Charge(1500, at); err != nil {
			b.Fatal(err)
		}
	}
}
