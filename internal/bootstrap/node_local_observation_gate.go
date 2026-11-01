package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"errors"
	"sync"
	"time"
)

// These aliases preserve the existing local gate API. The shared values carry
// committed binding/credit facts; constructing them does not issue authority.
type ObservationBinding = collector.ObservationBinding
type ObservationPermit = collector.ObservationPermit

func ObservationAccountingRule() [32]byte { return collector.ObservationAccountingRule() }

var (
	ErrObservationBinding = errors.New("observation binding invalid")
	ErrObservationUpdate  = errors.New("observation update invalid")
	ErrObservationLength  = errors.New("observation length invalid")
	ErrObservationCredit  = collector.ErrObservationBudgetExhausted
	ErrObservationRate    = collector.ErrObservationRateExceeded
	ErrObservationExpired = collector.ErrObservationLeaseExpired
	ErrObservationClosed  = errors.New("observation stopped")
)

// ObservationSnapshot counts only input admitted to the predicate. Unknown loss
// never invents byte lengths and never releases reserved credit.
type ObservationSnapshot struct {
	Bytes, Frames uint64
	UnknownInput  bool
	Stopped       error
}

// LocalObservationGate owns one local source incarnation. Consume and Update are
// serialized. The callback must use Context for the engine and join that engine
// before closing/releasing resources. There is no timer-based credit refill.
type LocalObservationGate struct {
	mu       sync.Mutex
	permit   ObservationPermit
	meter    *collector.ObservationMeter
	ctx      context.Context
	cancel   context.CancelFunc
	parent   context.Context
	timer    *time.Timer
	now      func() time.Time
	last     time.Time
	snapshot ObservationSnapshot
}

func validObservationPermit(p ObservationPermit, now time.Time) bool {
	return p.Binding.Valid() && p.Lease().Valid(now)
}

func NewLocalObservationGate(parent context.Context, expected ObservationBinding, p ObservationPermit, now func() time.Time) (*LocalObservationGate, error) {
	if parent == nil || parent.Err() != nil || now == nil || expected != p.Binding || !validObservationPermit(p, now()) || p.Sequence != 1 {
		return nil, ErrObservationBinding
	}
	base, err := collector.NewObservationMeter(p.Lease(), now())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	m := &LocalObservationGate{permit: p, meter: base, ctx: ctx, cancel: cancel, parent: parent, now: now, last: now()}
	// The lease callback takes the same mutex as a debit. Parent cancellation
	// propagates through ctx directly; no additional parent watcher is needed.
	// Once stopped, renewal cannot revive this incarnation.
	m.mu.Lock()
	m.timer = time.AfterFunc(p.LeaseUntil.Sub(m.last), m.expire)
	m.mu.Unlock()
	return m, nil
}

// An AfterFunc already dispatched before Update.Reset cannot be retracted.
// Compare the current lease under its debit/update mutex before stopping, so
// that obsolete firing cannot cancel a valid renewal which won that mutex.
func (m *LocalObservationGate) expire() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.snapshot.Stopped != nil {
		return
	}
	now := m.now()
	if now.Before(m.last) || !now.Before(m.permit.LeaseUntil) {
		m.stopLocked(ErrObservationExpired)
	}
}

func (m *LocalObservationGate) Context() context.Context { return m.ctx }

func (m *LocalObservationGate) stopLocked(err error) error {
	if m.snapshot.Stopped == nil {
		if err == nil {
			err = ErrObservationClosed
		}
		m.snapshot.Stopped = err
		m.timer.Stop()
		m.cancel()
	}
	return m.snapshot.Stopped
}

func (m *LocalObservationGate) Stop(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked(err)
}

func (m *LocalObservationGate) Close() {
	m.Stop(ErrObservationClosed)
}

func (m *LocalObservationGate) liveLocked(now time.Time) error {
	if m.snapshot.Stopped != nil {
		return m.snapshot.Stopped
	}
	if err := m.parent.Err(); err != nil {
		return m.stopLocked(err)
	}
	if now.Before(m.last) || !now.Before(m.permit.LeaseUntil) || !now.Before(m.permit.SessionUntil) {
		return m.stopLocked(ErrObservationExpired)
	}
	m.last = now
	return nil
}

// Consume debits the original engine length BEFORE any predicate/parser call.
// captured is only a consistency check; it is never substituted for wire.
func (m *LocalObservationGate) Consume(wire uint32, captured int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.liveLocked(now); err != nil {
		return err
	}
	if wire == 0 || captured < 0 || uint64(captured) > uint64(wire) {
		m.snapshot.UnknownInput = true
		return m.stopLocked(ErrObservationLength)
	}
	if uint64(wire) > uint64(m.permit.Credit)-m.snapshot.Bytes {
		return m.stopLocked(ErrObservationCredit)
	}
	if err := m.meter.Charge(int64(wire), now); err != nil {
		return m.stopLocked(err)
	}
	m.snapshot.Bytes += uint64(wire)
	m.snapshot.Frames++
	return nil
}

// Update accepts an exact duplicate without refilling anything. Every new update
// advances exactly one sequence with the same original binding/session/rate.
// Invalid updates stop this incarnation, rather than leaving ambiguous authority.
func (m *LocalObservationGate) Update(p ObservationPermit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.liveLocked(now); err != nil {
		return err
	}
	old := m.permit
	if p.Binding == old.Binding && p.Sequence == old.Sequence && p.Credit == old.Credit && p.BytesPerSecond == old.BytesPerSecond &&
		p.StartedAt.Equal(old.StartedAt) && p.SessionUntil.Equal(old.SessionUntil) && p.LeaseUntil.Equal(old.LeaseUntil) {
		return nil
	}
	if !validObservationPermit(p, now) || p.Binding != old.Binding || !p.StartedAt.Equal(old.StartedAt) || !p.SessionUntil.Equal(old.SessionUntil) || p.BytesPerSecond != old.BytesPerSecond ||
		old.Sequence == ^uint64(0) || p.Sequence != old.Sequence+1 || p.Credit < old.Credit || p.LeaseUntil.Before(old.LeaseUntil) {
		return m.stopLocked(ErrObservationUpdate)
	}
	if err := m.meter.Renew(p.Lease(), now); err != nil {
		return m.stopLocked(err)
	}
	m.permit = p
	m.timer.Reset(p.LeaseUntil.Sub(now))
	return nil
}

func (m *LocalObservationGate) LostSamples(n uint64) {
	if n == 0 {
		return
	}
	m.UnknownInput()
}

// UnknownInput records an unmeasurable gap without fabricating a lost count.
func (m *LocalObservationGate) UnknownInput() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshot.UnknownInput = true
	m.stopLocked(ErrObservationClosed)
}

func (m *LocalObservationGate) Snapshot() ObservationSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.snapshot
}
