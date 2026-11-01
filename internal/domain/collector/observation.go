package collector

import (
	"errors"
	"time"
)

var (
	ErrObservationInvalid         = errors.New("invalid observation lease")
	ErrObservationBudgetExhausted = errors.New("ObservationBudgetExhausted")
	ErrObservationLeaseExpired    = errors.New("observation lease expired")
	ErrObservationRateExceeded    = errors.New("observation rate exceeded")
)

// ObservationLease is an admitted cumulative credit ceiling for one original
// session and node/process fence. It contains no grant-issuing authority. Credit
// extensions travel with current-authority renewal over the private work channel.
type ObservationLease struct {
	SessionID, Fence                    string
	Sequence                            uint64
	StartedAt, SessionUntil, LeaseUntil time.Time
	Credit, MaxBytesPerSecond           int64
}

func (l ObservationLease) Valid(now time.Time) bool {
	return validUUID(l.SessionID) && validUUID(l.Fence) && l.Sequence > 0 && !l.StartedAt.IsZero() && !now.Before(l.StartedAt) && l.SessionUntil.After(l.StartedAt) && l.SessionUntil.Sub(l.StartedAt) <= time.Hour && now.Before(l.LeaseUntil) && !l.LeaseUntil.After(l.SessionUntil) && l.LeaseUntil.Sub(now) <= time.Minute && l.Credit > 0 && l.Credit <= 1<<40 && l.MaxBytesPerSecond > 0 && l.MaxBytesPerSecond <= 1<<30
}

// ObservationMeter is used under the frame callback's existing serialization.
// Charge must succeed before passing any frame to a sensitive predicate. Actual
// observed bytes are independent from conservative prepaid hub spend and retained
// output. Callers stop capture on refusal; no frame-processing fallback exists.
type ObservationMeter struct {
	lease    ObservationLease
	observed int64
	last     time.Time
	// Integer byte-nanoseconds avoid floating-point drift and allocations. The
	// one-second burst and <=1 GiB/s rate keep multiplication within int64.
	tokens int64
}

func NewObservationMeter(l ObservationLease, now time.Time) (*ObservationMeter, error) {
	if !l.Valid(now) {
		return nil, ErrObservationInvalid
	}
	return &ObservationMeter{lease: l, last: now, tokens: l.MaxBytesPerSecond * int64(time.Second)}, nil
}

func (m *ObservationMeter) ObservedBytes() int64 { return m.observed }

func (m *ObservationMeter) Charge(wire int64, now time.Time) error {
	if wire <= 0 || wire > 1<<32-1 || now.Before(m.last) {
		return ErrObservationInvalid
	}
	if !now.Before(m.lease.LeaseUntil) || !now.Before(m.lease.SessionUntil) {
		return ErrObservationLeaseExpired
	}
	if wire > m.lease.Credit-m.observed {
		return ErrObservationBudgetExhausted
	}
	elapsed := min(now.Sub(m.last), time.Second)
	burst := m.lease.MaxBytesPerSecond * int64(time.Second)
	tokens := min(burst, m.tokens+int64(elapsed)*m.lease.MaxBytesPerSecond)
	cost := wire * int64(time.Second)
	if cost > tokens {
		return ErrObservationRateExceeded
	}
	m.tokens, m.last, m.observed = tokens-cost, now, m.observed+wire
	return nil
}

// Renew accepts the next sequence once, or an identical lost-reply replay. It
// never resets counters, rate tokens or original session bounds. A renewal with
// unchanged Credit keeps already-prepaid bytes usable when the parent has no
// unallocated credit. Expired sessions cannot be revived.
func (m *ObservationMeter) Renew(next ObservationLease, now time.Time) error {
	old := m.lease
	if !now.Before(old.LeaseUntil) || !next.Valid(now) {
		return ErrObservationLeaseExpired
	}
	if next.SessionID != old.SessionID || next.Fence != old.Fence || !next.StartedAt.Equal(old.StartedAt) || !next.SessionUntil.Equal(old.SessionUntil) || next.MaxBytesPerSecond != old.MaxBytesPerSecond || next.Credit < old.Credit || next.LeaseUntil.Before(old.LeaseUntil) {
		return ErrObservationInvalid
	}
	if next.Sequence == old.Sequence {
		if next.Credit != old.Credit || !next.LeaseUntil.Equal(old.LeaseUntil) {
			return ErrObservationInvalid
		}
		return nil
	}
	if old.Sequence == ^uint64(0) || next.Sequence != old.Sequence+1 {
		return ErrObservationInvalid
	}
	m.lease = next
	return nil
}
