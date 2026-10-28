package bootstrap

import (
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// ObservationRule pins wire-byte token accounting, including its one-second
// initial burst. This is local enforcement, never an authority issuer.
func ObservationAccountingRule() [32]byte {
	return sha256.Sum256([]byte("wire-token-bucket-v1;burst=rate;whole-frame;no-refund"))
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

func (b ObservationBinding) valid() bool {
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

func (p ObservationPermit) lease() collector.ObservationLease {
	return collector.ObservationLease{SessionID: p.Binding.SessionID, Fence: p.Binding.Fence, Sequence: p.Sequence, StartedAt: p.StartedAt, SessionUntil: p.SessionUntil, LeaseUntil: p.LeaseUntil, Credit: p.Credit, MaxBytesPerSecond: p.BytesPerSecond}
}
func validObservationPermit(p ObservationPermit, now time.Time) bool {
	return p.Binding.valid() && p.lease().Valid(now)
}

func NewLocalObservationGate(parent context.Context, expected ObservationBinding, p ObservationPermit, now func() time.Time) (*LocalObservationGate, error) {
	if parent == nil || parent.Err() != nil || now == nil || expected != p.Binding || !validObservationPermit(p, now()) || p.Sequence != 1 {
		return nil, ErrObservationBinding
	}
	base, err := collector.NewObservationMeter(p.lease(), now())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	m := &LocalObservationGate{permit: p, meter: base, ctx: ctx, cancel: cancel, parent: parent, now: now, last: now()}
	// The lease callback takes the same mutex as a debit. Parent cancellation
	// propagates through ctx directly; no additional parent watcher is needed.
	// Once stopped, renewal cannot revive this incarnation.
	m.mu.Lock()
	m.timer = time.AfterFunc(p.LeaseUntil.Sub(m.last), func() { m.Stop(ErrObservationExpired) })
	m.mu.Unlock()
	return m, nil
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
	if err := m.meter.Renew(p.lease(), now); err != nil {
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
