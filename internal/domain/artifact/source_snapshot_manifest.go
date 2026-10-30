package artifact

import (
	"time"
)

// SourceSnapshotManifest preserves the original source and reviewed selection
// inside the encrypted artifact, independently of transient source SQL rows.
// Both documents are supplied from accepted facts, never from producer output.
type SourceSnapshotManifest struct {
	CanonicalScope []byte `json:"canonicalScope"`
	Binding        []byte `json:"binding"`
}

func (m *SourceSnapshotManifest) Valid() bool {
	return m != nil && len(m.CanonicalScope) > 0 && len(m.CanonicalScope) <= 16<<10 && len(m.Binding) > 0 && len(m.Binding) <= 4<<10
}

// SourceSnapshotAcquisition separates the original observation interval from
// the requested window and from the later snapshot processing completion.
func SourceSnapshotAcquisition(o SourceSnapshotCoverage) (time.Time, time.Time) {
	start, end := SourceSnapshotAnchor(o.Request), o.Request.T0.Add(o.Request.After)
	if o.Request.SourceHardUntil.Before(end) {
		end = o.Request.SourceHardUntil
	}
	if !o.SourceStoppedAt.IsZero() && o.SourceStoppedAt.Before(end) {
		end = o.SourceStoppedAt
	}
	if !o.SourceClosedAt.IsZero() && o.SourceClosedAt.Before(end) {
		end = o.SourceClosedAt
	}
	return start, end
}

func (m *SourceSnapshotManifest) Clone() *SourceSnapshotManifest {
	if m == nil {
		return nil
	}
	return &SourceSnapshotManifest{CanonicalScope: append([]byte(nil), m.CanonicalScope...), Binding: append([]byte(nil), m.Binding...)}
}
