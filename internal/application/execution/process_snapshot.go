package execution

import (
	"context"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

// ProcessRuntimeMember comes only from the node's qualified runtime adapter.
// Container identity is provenance; callers cannot supply a member selector.
type ProcessRuntimeMember struct {
	ID, SandboxID, PodUID string
	RestartCount          uint32
	MainPID               uint32
	Running               bool
}

type ProcessRuntimeReader interface {
	PodProcesses(context.Context, artifact.PinnedPod) ([]ProcessRuntimeMember, error)
	CurrentProcessMember(context.Context, ProcessRuntimeMember) (ProcessRuntimeMember, error)
}

type ProcessSnapshotRequest = value.ProcessSnapshotRequest
