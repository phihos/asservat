package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"time"
)

type ProcessesRecorder interface {
	StartProcesses(context.Context, artifact.PinnedPod, time.Time, time.Time) (time.Time, error)
}

type ProcessesCanceller interface {
	CancelProcesses(context.Context, collector.ProcessStop) error
}
