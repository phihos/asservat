package execution

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"context"
	"time"
)

// LiveManualWork is the original accepted finite work and its actual started
// regional execution. It is routing/provenance, not a live disclosure permit.
// The actual node holder supplies the original source start/end independently;
// Execution.Binding.NotAfter is only the preparation deadline.
type LiveManualWork struct {
	Work                   APIContextWork
	Execution              value.APIExecution
	Observation            *collector.ObservationBinding
	Arguments              *collector.ArgumentObservationBinding
	ObservedAt, FreshUntil time.Time
}

type LiveManualWorks interface {
	LiveManualTarget(context.Context, string) (authorization.Target, error)
	ReadLiveManualWork(context.Context, []string, artifact.RecoveryProof) ([]LiveManualWork, error)
	// UUID cursor is the last CaptureID. More pages never create source state.
	ListLiveManualWork(context.Context, authorization.WorkloadTarget, string, int, artifact.RecoveryProof) ([]LiveManualWork, string, error)
}
