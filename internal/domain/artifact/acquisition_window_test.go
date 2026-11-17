package artifact

import (
	"testing"
	"time"
)

func TestProfileAcquisitionWindowCanonicalDisplayMetadata(t *testing.T) {
	start := time.Date(2026, 11, 4, 9, 0, 0, 123456000, time.UTC)
	w := AcquisitionWindow{StartedAt: start, CompletedAt: start.Add(time.Second)}
	if !w.Valid() {
		t.Fatal("valid microsecond window rejected")
	}
	for _, mode := range []string{"missing-start", "missing-end", "reversed", "offset", "nanoseconds"} {
		t.Run(mode, func(t *testing.T) {
			bad := w
			switch mode {
			case "missing-start":
				bad.StartedAt = time.Time{}
			case "missing-end":
				bad.CompletedAt = time.Time{}
			case "reversed":
				bad.CompletedAt = start.Add(-time.Microsecond)
			case "offset":
				bad.StartedAt = start.In(time.FixedZone("source", 3600))
			case "nanoseconds":
				bad.CompletedAt = bad.CompletedAt.Add(time.Nanosecond)
			}
			if bad.Valid() {
				t.Fatal("noncanonical window accepted")
			}
		})
	}
	instant := w
	instant.CompletedAt = instant.StartedAt
	if !instant.Valid() {
		t.Fatal("microsecond normalization may collapse a short snapshot")
	}
	clone := w.Clone()
	clone.CompletedAt = start
	if w.CompletedAt.Equal(clone.CompletedAt) {
		t.Fatal("window clone aliases original")
	}
	var absent *AcquisitionWindow
	if absent.Clone() != nil {
		t.Fatal("unknown window invented")
	}
}
