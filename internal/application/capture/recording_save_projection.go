package capture

import (
	value "asservat.local/asservat/internal/domain/capture"
	"time"
)

type RecordingSavePreviewMetadata struct {
	Selected       []RecordingRow
	Before         time.Duration
	IncidentPodCap int
}

// The current private policy compiler accepts one packet action and explicitly
// rejects target.maxPods other than1. ObservedPods is the separate source cohort
// ceiling. Keep this backend limit in application metadata, not transport copy.
func recordingSaveIncidentPodCap(p value.RestartPolicy) int {
	if !p.Valid() || p.Recorder == nil {
		return 0
	}
	return 1
}
