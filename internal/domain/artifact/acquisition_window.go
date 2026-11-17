package artifact

import "time"

// AcquisitionWindow is verified display metadata about endpoint HTTP acquisition,
// not a sample-history interval, measured clock offset or serving-process proof.
// Values use UTC microseconds; sealed manifest/native precision is unchanged.
type AcquisitionWindow struct {
	StartedAt, CompletedAt time.Time
}

func (w AcquisitionWindow) Valid() bool {
	return !w.StartedAt.IsZero() && !w.CompletedAt.IsZero() && !w.CompletedAt.Before(w.StartedAt) && w.StartedAt.Location() == time.UTC && w.CompletedAt.Location() == time.UTC && w.StartedAt.Nanosecond()%1000 == 0 && w.CompletedAt.Nanosecond()%1000 == 0
}

func (w AcquisitionWindow) Equal(o AcquisitionWindow) bool {
	return w.StartedAt.Equal(o.StartedAt) && w.CompletedAt.Equal(o.CompletedAt)
}

func (w *AcquisitionWindow) Clone() *AcquisitionWindow {
	if w == nil {
		return nil
	}
	out := *w
	return &out
}
