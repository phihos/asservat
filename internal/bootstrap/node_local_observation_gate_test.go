package bootstrap

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func localObservationFixture(t testing.TB, credit, rate int64) (*LocalObservationGate, ObservationPermit, *time.Time) {
	t.Helper()
	now := time.Now()
	binding := ObservationBinding{Scope: [32]byte{1}, ProgramDigest: [32]byte{2}, ExpectationDigest: [32]byte{3}, AccountingRule: ObservationAccountingRule(), SessionID: "00000000-0000-4000-8000-000000000001", Fence: "00000000-0000-4000-8000-000000000002", CaptureID: "capture", ActionID: "packet", PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch"}
	p := ObservationPermit{Binding: binding, StartedAt: now, SessionUntil: now.Add(time.Minute), LeaseUntil: now.Add(30 * time.Second), Sequence: 1, Credit: credit, BytesPerSecond: rate}
	m, err := NewLocalObservationGate(context.Background(), binding, p, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, p, &now
}

func TestObservationCreditOriginalWireAndDuplicateNoRefill(t *testing.T) {
	m, p, now := localObservationFixture(t, 200, 100)
	if err := m.Consume(100, 10); err != nil {
		t.Fatal(err)
	}
	// A private-wire round trip removes monotonic bits and normalizes zone.
	// Identical instants remain an exact replay and must not refill anything.
	p.StartedAt = p.StartedAt.UTC().Round(0)
	p.SessionUntil = p.SessionUntil.UTC().Round(0)
	p.LeaseUntil = p.LeaseUntil.UTC().Round(0)
	if err := m.Update(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(1, 1); !errors.Is(err, ErrObservationRate) {
		t.Fatal("duplicate refilled rate", err)
	}
	if s := m.Snapshot(); s.Bytes != 100 || s.Frames != 1 {
		t.Fatal(s)
	}
	// A fresh meter distinguishes cumulative prepaid ceiling from rate refill.
	m, p, now = localObservationFixture(t, 100, 100)
	if err := m.Consume(100, 10); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	p.Sequence++
	p.LeaseUntil = p.LeaseUntil.Add(time.Second)
	if err := m.Update(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(1, 1); !errors.Is(err, ErrObservationCredit) {
		t.Fatal("authority-only renewal refilled credit", err)
	}
	if s := m.Snapshot(); s.Bytes != 100 || s.Frames != 1 {
		t.Fatal(s)
	}
}

func TestObservationRenewalKeepsOriginalBindingAndSpend(t *testing.T) {
	for _, mode := range []string{"lower-sequence", "skip-sequence", "same-sequence-change", "lower-credit", "new-epoch", "new-boot", "new-action", "new-grant-scope", "new-program", "new-expectation", "new-rate", "new-session-end", "shorter-lease"} {
		t.Run(mode, func(t *testing.T) {
			m, p, _ := localObservationFixture(t, 100, 100)
			if err := m.Consume(60, 10); err != nil {
				t.Fatal(err)
			}
			old := p
			p.Sequence++
			p.Credit = 200
			switch mode {
			case "lower-sequence":
				p.Sequence = 0
			case "skip-sequence":
				p.Sequence++
			case "same-sequence-change":
				p.Sequence = old.Sequence
			case "lower-credit":
				p.Credit = 99
			case "new-epoch":
				p.Binding.CollectorEpoch = "replacement"
			case "new-boot":
				p.Binding.BootID = "replacement"
			case "new-action":
				p.Binding.ActionID = "replacement"
			case "new-program":
				p.Binding.ProgramDigest[0]++
			case "new-expectation":
				p.Binding.ExpectationDigest[0]++
			case "new-grant-scope":
				p.Binding.Scope[0]++
			case "new-rate":
				p.BytesPerSecond++
			case "new-session-end":
				p.SessionUntil = p.SessionUntil.Add(time.Second)
			case "shorter-lease":
				p.LeaseUntil = p.LeaseUntil.Add(-time.Second)
			}
			if err := m.Update(p); !errors.Is(err, ErrObservationUpdate) {
				t.Fatal(err)
			}
			if err := m.Update(old); err == nil {
				t.Fatal("stopped meter revived")
			}
			if s := m.Snapshot(); s.Bytes != 60 || s.Frames != 1 {
				t.Fatal(s)
			}
		})
	}
	m, p, now := localObservationFixture(t, 100, 100)
	if err := m.Consume(60, 10); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Second)
	p.Sequence++
	p.Credit = 150
	p.LeaseUntil = p.LeaseUntil.Add(time.Second)
	if err := m.Update(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(p); err != nil {
		t.Fatal(err)
	}
	if err := m.Consume(90, 10); err != nil {
		t.Fatal(err)
	}
	if s := m.Snapshot(); s.Bytes != 150 || s.Frames != 2 {
		t.Fatal(s)
	}
	if err := m.Consume(1, 1); !errors.Is(err, ErrObservationCredit) {
		t.Fatal(err)
	}
}

func TestObservationFailsBeforePredicateForInvalidAndExpiredInput(t *testing.T) {
	for _, mode := range []string{"missing", "short-length", "negative-captured", "lease", "session", "backward-clock", "lost-samples"} {
		t.Run(mode, func(t *testing.T) {
			m, p, now := localObservationFixture(t, 100, 100)
			wire, n := uint32(10), 10
			switch mode {
			case "missing":
				wire = 0
			case "short-length":
				wire = 9
			case "negative-captured":
				n = -1
			case "lease":
				*now = p.LeaseUntil
			case "session":
				*now = p.SessionUntil
			case "backward-clock":
				*now = now.Add(-time.Nanosecond)
			case "lost-samples":
				m.LostSamples(1)
			}
			if err := m.Consume(wire, n); err == nil {
				t.Fatal("accepted invalid observation")
			}
			s := m.Snapshot()
			if s.Bytes != 0 || s.Frames != 0 || s.UnknownInput != (mode == "lost-samples" || mode == "missing" || mode == "short-length" || mode == "negative-captured") {
				t.Fatal(s)
			}
			if m.Context().Err() == nil {
				t.Fatal("engine context still live")
			}
		})
	}
}

func TestObservationIdleLeaseAndCanceledParentStopEngine(t *testing.T) {
	for _, mode := range []string{"lease", "parent"} {
		t.Run(mode, func(t *testing.T) {
			sample, p, _ := localObservationFixture(t, 100, 100)
			sample.Close()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			p.StartedAt = time.Now()
			p.LeaseUntil = p.StartedAt.Add(15 * time.Millisecond)
			p.SessionUntil = p.StartedAt.Add(time.Second)
			m, err := NewLocalObservationGate(parent, p.Binding, p, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if mode == "parent" {
				cancel()
			}
			select {
			case <-m.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("idle engine not stopped")
			}
			if err := m.Consume(1, 1); err == nil {
				t.Fatal("predicate after cancellation")
			}
		})
	}
}

func TestObservationConcurrentCreditNeverOverspends(t *testing.T) {
	m, _, _ := localObservationFixture(t, 100, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = m.Consume(10, 1) }()
	}
	wg.Wait()
	if s := m.Snapshot(); s.Bytes != 100 || s.Frames != 10 || !errors.Is(s.Stopped, ErrObservationCredit) {
		t.Fatal(s)
	}
}

func TestObservationConstructorRejectsRestartAndInvalidRule(t *testing.T) {
	sample, p, _ := localObservationFixture(t, 100, 100)
	sample.Close()
	for _, mode := range []string{"epoch", "sequence", "rule", "missing-node", "expired"} {
		t.Run(mode, func(t *testing.T) {
			q := p
			expected := p.Binding
			switch mode {
			case "epoch":
				expected.CollectorEpoch = "new"
			case "sequence":
				q.Sequence++
			case "rule":
				q.Binding.AccountingRule = [32]byte{}
			case "missing-node":
				q.Binding.NodeUID = ""
			case "expired":
				q.LeaseUntil = time.Now().Add(-time.Second)
			}
			if m, err := NewLocalObservationGate(context.Background(), expected, q, time.Now); err == nil {
				m.Close()
				t.Fatal("adopted invalid/restarted permit")
			}
		})
	}
}

func TestLocalObservationRenewalMovesIdleTimerWithoutRefilling(t *testing.T) {
	sample, p, _ := localObservationFixture(t, 100, 100)
	sample.Close()
	now := time.Now()
	p.StartedAt = now
	p.SessionUntil = now.Add(time.Second)
	p.LeaseUntil = now.Add(200 * time.Millisecond)
	m, err := NewLocalObservationGate(context.Background(), p.Binding, p, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err = m.Consume(100, 1); err != nil {
		t.Fatal(err)
	}
	p.Sequence++
	p.LeaseUntil = now.Add(450 * time.Millisecond)
	if err = m.Update(p); err != nil {
		t.Fatal(err)
	}
	// The original lease timer must no longer own this still-idle source.
	select {
	case <-m.Context().Done():
		t.Fatal("renewed idle lease stopped at old deadline")
	case <-time.After(250 * time.Millisecond):
	}
	if m.Snapshot().Bytes != 100 {
		t.Fatal("renewal changed measured spend")
	}
	select {
	case <-m.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("new lease did not stop idle engine")
	}
	if err = m.Update(p); err == nil {
		t.Fatal("expired idle lease revived")
	}
}

func TestLocalObservationQueuedOldTimerCannotStopRenewedLease(t *testing.T) {
	sample, p, _ := localObservationFixture(t, 100, 100)
	sample.Close()
	base := time.Now()
	p.StartedAt = base
	p.SessionUntil = base.Add(time.Minute)
	p.LeaseUntil = base.Add(200 * time.Millisecond)
	entered, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	clock := func() time.Time {
		if hold.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return base.Add(time.Millisecond)
	}
	m, err := NewLocalObservationGate(context.Background(), p.Binding, p, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dispatched, finished := make(chan struct{}), make(chan struct{})
	var dispatchedOnce, finishedOnce sync.Once
	m.mu.Lock()
	if !m.timer.Stop() {
		m.mu.Unlock()
		t.Fatal("initial timer unexpectedly dispatched before setup")
	}
	// Wrap the real expiration callback solely to join its already-dispatched
	// execution; no test-only production hook or race-dependent sleep is needed.
	m.timer = time.AfterFunc(time.Until(p.LeaseUntil), func() {
		dispatchedOnce.Do(func() { close(dispatched) })
		m.expire()
		finishedOnce.Do(func() { close(finished) })
	})
	m.mu.Unlock()
	hold.Store(true)
	renewed := make(chan error, 1)
	p.Sequence++
	p.LeaseUntil = base.Add(5 * time.Second)
	go func() { renewed <- m.Update(p) }()
	<-entered // Update sampled a valid old instant while holding the gate mutex.
	select {
	case <-dispatched:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("old callback was not dispatched")
	}
	close(release)
	if err = <-renewed; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("obsolete callback did not join")
	}
	if m.Context().Err() != nil || m.Snapshot().Stopped != nil {
		t.Fatal("old timer stopped a renewed source", m.Snapshot())
	}
}
