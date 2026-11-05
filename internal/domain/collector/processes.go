package collector

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/execution"
	"time"
)

const MechanismProcesses Mechanism = "processSnapshot"
const WorkProcesses WorkKind = "processSnapshot"
const WorkCancelProcesses WorkKind = "cancelProcessSnapshot"

type ProcessCapture struct {
	CaptureID, CollectorEpoch string
	ExpectationDigest         artifact.Digest
	Request                   execution.ProcessSnapshotRequest
}

func (p ProcessCapture) Valid() bool {
	return authorization.UUID(p.CaptureID) && authorization.UUID(p.CollectorEpoch) && p.ExpectationDigest != (artifact.Digest{}) && p.Request.Valid()
}

type ProcessResult struct {
	WorkID, CaptureID, PodUID, NodeUID, NodeBootID string
	ExpectationDigest                              artifact.Digest
	StartedAt, CompletedAt                         time.Time
	NativeBytes                                    int64
	Failure                                        Reason
}

func (p ProcessResult) Valid() bool {
	if !authorization.UUID(p.WorkID) || !authorization.UUID(p.CaptureID) || p.PodUID == "" || p.NodeUID == "" || !authorization.UUID(p.NodeBootID) || p.ExpectationDigest == (artifact.Digest{}) || p.StartedAt.IsZero() || p.CompletedAt.Before(p.StartedAt) || p.CompletedAt.Sub(p.StartedAt) > 35*time.Second || p.NativeBytes < 0 || p.NativeBytes > artifact.ProcessNativeLimit {
		return false
	}
	if p.Failure == "" {
		return p.NativeBytes > 0 && p.CompletedAt.Sub(p.StartedAt) <= 5*time.Second
	}
	return p.NativeBytes == 0 && (p.Failure == ReasonCaptureFailed || p.Failure == ReasonTargetNotFound || p.Failure == ReasonCaptureBusy)
}
