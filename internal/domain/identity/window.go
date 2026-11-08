package identity

import "time"

// PolicyObservationInterval bounds reuse of one completed protected delivery
// policy observation (ADR-214/311).
const PolicyObservationInterval = 60 * time.Second

// SQLFencedInterval bounds proofs that SQL fences persist and re-check
// (recovery observations in migrations 00049/00054); those fences refuse
// longer windows until a migration relaxes them.
const SQLFencedInterval = 5 * time.Second

// WindowKind names the interval one completed check may be used for, so a
// producer and its consumer cannot disagree about it.
type WindowKind uint8

const (
	_ WindowKind = iota
	Recheck
	PolicyObservation
	SQLFenced
)

func (k WindowKind) Interval() time.Duration {
	switch k {
	case Recheck:
		return AuthorityRecheckInterval
	case PolicyObservation:
		return PolicyObservationInterval
	case SQLFenced:
		return SQLFencedInterval
	}
	return 0
}

// Window is the validity of one completed check. It starts at the check's own
// start and is built only by Check; Narrow can only shorten it. The fields are
// unexported so no caller can move From or extend Until. A zero Window is
// invalid.
type Window struct {
	from, until time.Time
	kind        WindowKind
}

// Check starts the window of a check that started at start.
func Check(start time.Time, kind WindowKind) Window {
	if start.IsZero() || kind.Interval() <= 0 {
		return Window{}
	}
	return Window{from: start, until: start.Add(kind.Interval()), kind: kind}
}

// Narrow ends the window no later than every t. A zero t makes it invalid.
func (w Window) Narrow(t ...time.Time) Window {
	for _, v := range t {
		if v.Before(w.until) {
			w.until = v
		}
	}
	return w
}

func (w Window) From() time.Time  { return w.from }
func (w Window) Until() time.Time { return w.until }
func (w Window) Kind() WindowKind { return w.kind }
func (w Window) Valid(now time.Time) bool {
	return w.kind.Interval() > 0 && Fresh(w.from, w.until, now, w.kind.Interval())
}
