package live

import "time"

// ClockProof is supplied only by an authenticated finite source exchange. The
// remote monotonic sample is bracketed by this caller's original round trip;
// its uncertainty is not a wall-clock synchronization assumption. Source stamps
// and the sample must use the same unchanged boot/monotonic clock identity.
type ClockProof struct {
	SourceID, BootID, Clock string
	RemoteNanos             int64
	StartedAt, ReceivedAt   time.Time
	SampleUncertainty       time.Duration
}

func (p ClockProof) Valid() bool {
	return p.SourceID != "" && p.BootID != "" && (p.Clock == "monotonic" || p.Clock == "boottime") && p.RemoteNanos > 0 && !p.StartedAt.IsZero() && !p.ReceivedAt.Before(p.StartedAt) && p.SampleUncertainty >= 0 && p.ReceivedAt.Sub(p.StartedAt)+2*p.SampleUncertainty <= 5*time.Second
}

// Place uses the earliest possible event time for expiry. The midpoint and
// uncertainty describe placement; expiry cannot gain time from network delay.
func (p ClockProof) Place(stamp int64, source, boot, clock string, privacy, watch, authority time.Time) (at, expires time.Time, uncertainty int, ok bool) {
	if !p.Valid() || stamp <= 0 || stamp > p.RemoteNanos || source != p.SourceID || boot != p.BootID || clock != p.Clock {
		return
	}
	age := time.Duration(p.RemoteNanos - stamp)
	if age >= RowAge {
		return time.Time{}, time.Time{}, 0, false
	}
	span := p.ReceivedAt.Sub(p.StartedAt)
	earliest := p.StartedAt.Add(-age - p.SampleUncertainty)
	at = p.StartedAt.Add(span/2 - age)
	expires = earliest.Add(RowAge)
	for _, end := range []time.Time{privacy, watch, authority} {
		if end.IsZero() {
			return time.Time{}, time.Time{}, 0, false
		}
		if end.Before(expires) {
			expires = end
		}
	}
	uncertainty = int((span/2 + p.SampleUncertainty + time.Millisecond - 1) / time.Millisecond)
	ok = at.Year() >= 1970 && at.Year() <= 9999 && uncertainty <= 5000 && p.ReceivedAt.Before(expires)
	return
}
