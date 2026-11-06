package artifact

import "time"

// LogCapture is the immutable finite whole-Pod action, not read authority.
// Container and runtime identities are acquired provenance, never selectors.
type LogCapture struct {
	ActionID                  string
	BeforeMillis, AfterMillis int64
	Streams                   string
	MaxNativeBytes            int64
	TimeoutMillis             int64
	// Composition is accepted control metadata, never log bytes or origins.
	Composition []byte
}

func (l *LogCapture) Valid() bool {
	return l != nil && recorderActionID(l.ActionID) && l.Streams == "combined" &&
		l.BeforeMillis >= 0 && l.BeforeMillis <= int64(24*time.Hour/time.Millisecond) &&
		l.AfterMillis >= 0 && l.AfterMillis <= int64(time.Minute/time.Millisecond) &&
		l.TimeoutMillis > l.AfterMillis && l.TimeoutMillis <= int64(5*time.Minute/time.Millisecond) &&
		l.BeforeMillis+l.AfterMillis > 0 && l.MaxNativeBytes > 0 && l.MaxNativeBytes <= LogNativeLimit && len(l.Composition) <= 64<<10
}

func (l *LogCapture) Clone() *LogCapture {
	if l == nil {
		return nil
	}
	out := *l
	out.Composition = append([]byte(nil), l.Composition...)
	return &out
}

// Window preserves the original accepted incident/admission clock. Fetch and
// retry times never supply a replacement anchor.
func (l *LogCapture) Window(anchor time.Time) (time.Time, time.Time, error) {
	if !l.Valid() || anchor.IsZero() {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	start := anchor.Add(-time.Duration(l.BeforeMillis) * time.Millisecond)
	end := anchor.Add(time.Duration(l.AfterMillis) * time.Millisecond)
	if start.Year() < 1 || end.Year() > 9999 {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	return start, end, nil
}
