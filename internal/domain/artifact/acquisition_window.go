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

// CatalogFacts are the native size and, for Go profiles, the acquisition
// window that publication stored in the catalog row. Every read compares
// them with the authenticated manifest (REQ-EVD-001).
type CatalogFacts struct {
	NativeBytes int64
	Acquisition *AcquisitionWindow `json:",omitempty"`
}

// Matches reports whether the authenticated manifest size and interval equal
// the catalog row. Only a Go profile has a stored acquisition window, kept in
// UTC microseconds.
func (f CatalogFacts) Matches(profile bool, nativeBytes int64, started, completed time.Time) bool {
	if f.NativeBytes != nativeBytes || profile != (f.Acquisition != nil) {
		return false
	}
	return !profile || f.Acquisition.Equal(AcquisitionWindow{StartedAt: started.Truncate(time.Microsecond), CompletedAt: completed.Truncate(time.Microsecond)})
}
