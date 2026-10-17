package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// ContextDownloadAttachments reads the original paid first-context worker and
// metadata attempt. It cannot start a worker, prepare data, bind keys, or invent
// a current Pod/TLS proof from historical enrollment. The actual NativeObserve
// conversation independently authenticates the currently connected process.
type ContextDownloadAttachments interface {
	ReadContextDownloadAttachment(context.Context, string, artifact.DownloadAuthority) (ContextDownloadAttachment, error)
}
type ContextDownloadAttachment struct {
	SessionID     string
	Scope         artifact.DownloadScope
	State         artifact.DownloadState
	Found         bool
	Intent        authorization.DownloadWorkerIntent
	Worker        *authorization.DownloadWorker
	Enrollment    *authorization.WorkerEnrollment
	ActivatedPeer *authorization.KeyPeer
	// These are passive SQL availability facts, not peer or byte authority.
	NativeBusy, ResponseBusy, NativeUncertain bool
	NativeTransitions                         int64
	MetadataAttempted                         bool
	Preparation                               *artifact.DownloadPreparation
	ObservedAt, ValidUntil                    time.Time
}

func (s ContextDownloadAttachment) Valid(now time.Time) bool {
	if !authorization.UUID(s.SessionID) || !s.Scope.Valid() || !s.State.Valid() || !identity.Fresh(s.ObservedAt, s.ValidUntil, now, artifact.DownloadLease) {
		return false
	}
	if !s.Found {
		return s.Intent == (authorization.DownloadWorkerIntent{}) && s.Worker == nil && s.Enrollment == nil && s.ActivatedPeer == nil && !s.MetadataAttempted && s.Preparation == nil && !s.NativeBusy && !s.ResponseBusy && !s.NativeUncertain && s.NativeTransitions == 0
	}
	if s.NativeTransitions < 0 || s.NativeTransitions > 65536 {
		return false
	}
	if !s.Intent.Valid() || s.Intent.SessionID != s.SessionID || s.Intent.Authority.Scope != s.Scope || s.Intent.Generation != 1 || s.ValidUntil.After(s.Intent.RunUntil) {
		return false
	}
	if s.Worker != nil && (!s.Worker.Valid() || s.Worker.Intent != s.Intent) {
		return false
	}
	if s.Enrollment != nil && (s.Worker == nil || !s.Enrollment.Valid() || s.Enrollment.Worker != *s.Worker) {
		return false
	}
	if s.ActivatedPeer != nil && (s.Enrollment == nil || !s.ActivatedPeer.Valid(now) || s.ActivatedPeer.Role != "acquisition" || s.ActivatedPeer.InstallationID != s.Enrollment.Worker.Binding.InstallationID || s.ActivatedPeer.PeerID != s.Enrollment.Worker.Binding.PodUID) {
		return false
	}
	return s.Preparation == nil || (s.MetadataAttempted && s.Enrollment != nil && s.Preparation.Valid() && s.Preparation.SessionID == s.SessionID)
}
