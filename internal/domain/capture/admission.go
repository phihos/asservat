// Package capture contains accepted operation values. Admission reserves work;
// an accepted row is not an execution permit or a readable artifact.
package capture

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

var (
	ErrInvalid              = errors.New("invalid context admission")
	ErrDenied               = errors.New("context admission no longer authorized")
	ErrChanged              = errors.New("context admission inputs changed")
	ErrUnavailable          = errors.New("context admission unavailable")
	ErrCapacity             = errors.New("context allocation unavailable")
	ErrConflict             = errors.New("capture idempotency conflict")
	ErrAcquisitionClosed    = errors.New("original capture acquisition interval ended")
	ErrPreparationUncertain = errors.New("original capture preparation already owned or spent")
)

const PendingAudit = "accepted_pending_audit"
const IntentAudited = "intent_audited"

// StorageBinding is supplied only by the protected configuration reconciler.
// Allocation ownership is permanent in this initial facet; replacement/shrink
// require explicit draining, not reassignment of another workload's allocation.
type StorageBinding struct {
	RootID, ClusterID, NamespaceUID, WorkloadUID, AllocationID string
	Revision                                                   identity.Revision
	ObservedAt, FreshUntil                                     time.Time
}

func (b StorageBinding) Valid(now time.Time) bool {
	return authorization.UUID(b.RootID) && authorization.UUID(b.ClusterID) && authorization.UUID(b.AllocationID) && identity.Text(b.NamespaceUID, 64) && identity.Text(b.WorkloadUID, 64) && b.Revision.Valid() && identity.Fresh(b.ObservedAt, b.FreshUntil, now, 30*time.Second)
}
func (b StorageBinding) Matches(t authorization.Target) bool {
	return b.ClusterID == t.ClusterID && b.NamespaceUID == t.NamespaceUID && b.WorkloadUID == t.WorkloadUID
}

// Admission is an internal coordinator input, never an HTTP or CRD shape. The
// authenticated original authored intent has its own digest, distinct from scope.
type Admission struct {
	Recovery               artifact.RecoveryProof
	RootID, IdempotencyKey string
	SubmissionDigest       artifact.Digest
	Plan                   planning.ContextPlan
	Eligibility            authorization.CaptureEligibility
	Storage                StorageBinding
	Registration           artifact.Registration
	CaseID, OccurrenceID   string
}

// Accepted intentionally contains no "start" method or flag. Intent audit,
// current execution authority and local effect fencing precede dispatch.
type Accepted struct {
	CaptureID, State              string
	ScopeDigest, SubmissionDigest artifact.Digest
	Expectation                   artifact.ContextExpectation
	Pin                           artifact.PinnedPod
	CreatedAt, Deadline           time.Time
	Replay                        bool
	// MetadataValidUntil bounds this response only; never persisted or authority for a later request.
	MetadataValidUntil time.Time `json:"-"`
}
