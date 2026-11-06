package evidence

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// LogsRecorder transfers one prepared artifact to the regional holder only
// after the original API start was consumed. The expectation carries its fixed
// requested window; neither this start nor a retry supplies another anchor.
type LogsRecorder interface {
	StartLogs(context.Context, artifact.PinnedPod, time.Time, time.Time) (time.Time, error)
}
