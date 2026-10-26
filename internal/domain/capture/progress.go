package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const MaxProgressRevision int64 = 1000000000

// ProgressQuery is an internal fresh read request, not a transport shape.
type ProgressQuery struct {
	RootID, CaptureID string
	Identity          identity.Identity
	Recovery          artifact.RecoveryProof
}

func (q ProgressQuery) Valid(now time.Time) bool {
	return authorization.UUID(q.RootID) && authorization.UUID(q.CaptureID) && q.Identity.Valid(now) && q.Recovery.Valid(now)
}

// ContextProgressObservation is private authorized control metadata. Candidate
// case/artifact IDs are not navigation authority or readable evidence references.
// No status field authorizes execution, disclosure or release of capacity.
type ContextProgressObservation struct {
	CaptureID, CandidateCaseID, CandidateArtifactID string
	Target                                          authorization.Target
	Revision                                        int64
	Phase, ActionPhase, ReasonCode                  string
	CreatedAt, Deadline                             time.Time
	ObservedAt, ValidUntil                          time.Time
	// ShareID is the capture-time share's ID when the accepted capture
	// carries a sharing instruction (ADR-235); empty otherwise.
	ShareID string
}

func (p ContextProgressObservation) Valid(now time.Time) bool {
	if !authorization.UUID(p.CaptureID) || !authorization.UUID(p.CandidateCaseID) || !authorization.UUID(p.CandidateArtifactID) || !p.Target.Valid() || p.ShareID != "" && !authorization.UUID(p.ShareID) || p.Revision < 1 || p.Revision > MaxProgressRevision || !identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) || p.CreatedAt.IsZero() || !p.Deadline.After(p.CreatedAt) {
		return false
	}
	switch p.Phase {
	case "Pending":
		return p.ActionPhase == "Pending" && (p.ReasonCode == "IntentAuditPending" || p.ReasonCode == "DispatchUnconfirmed")
	case "Running":
		return p.ActionPhase == "Running" && p.ReasonCode == "AcquisitionStarted"
	case "Failed":
		return p.ActionPhase == "Failed" && p.ReasonCode == "AcquisitionFailed" || p.ActionPhase == "TargetGone" && p.ReasonCode == "PinnedPodGone" || p.ActionPhase == "Denied" && p.ReasonCode == "PodStatusDenied"
	case "Finalizing":
		return p.ActionPhase == "Finalizing" && (p.ReasonCode == "VerificationPending" || p.ReasonCode == "VerificationAuditPending" || p.ReasonCode == "PublicationPending")
	case "Succeeded":
		return p.ActionPhase == "Succeeded" && p.ReasonCode == "Published"
	case "Indeterminate":
		return p.ActionPhase == "Indeterminate" && (p.ReasonCode == "DeadlineOutcomeUnconfirmed" || p.ReasonCode == "StorageOutcomeUnconfirmed")
	}
	return false
}

// ContextProgress contains only the public capture-level projection. A case ID
// is populated only by the separate current case-navigation authorizer.
type ContextProgress struct {
	CaptureID, CaseID              string
	Revision                       int64
	Phase, ActionPhase, ReasonCode string
	CanCancel                      bool
	RetryAfterSeconds              int
	CreatedAt, Deadline            time.Time
	// Sharing is reported separately from capture progress (ADR-235); nil
	// when the capture carries no sharing instruction.
	Sharing *ContextSharingStatus
	// ValidUntil is an internal delivery fence, never part of public JSON.
	ValidUntil time.Time `json:"-"`
}
