package analysis

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type CurrentContextProjectionAuthority interface {
	ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error)
	CheckProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionScope) (value.ContextProjectionAuthority, error)
}

type ContextProjectionRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

type ContextProjectionRoutes interface {
	ResolveContextProjection(context.Context, value.ContextExcerptSelection, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error)
}

type ContextQueryPlans interface {
	ContextQueryPlan(context.Context, value.ContextProjectionAuthority) (value.ContextQueryPlan, error)
}

// ContextQueryInvocation is the original process-owned C-20 invocation, created
// only after C-08 acknowledges its intent. It does not implement another audit
// journal/writer. CheckOutcome recognizes only the exact immutable delivery
// association serialized, validated and acknowledged by the existing wrapper.
type ContextQueryInvocation interface {
	Invocation(context.Context) (value.ContextQueryCall, error)
	CheckInput(context.Context, ContextQueryInput) error
	CheckIntent(context.Context, value.ContextQueryCall) error
	CheckOutcome(context.Context, *ContextProjectionDelivery) error
}

// Exactly one branch is populated for the invocation's fixed tool. The existing
// C-20 owner compares it with its normalized input before any effect; C-18
// neither computes another MAC nor accepts an unrelated acknowledged intent.
type ContextQueryInput struct {
	Selection value.ContextExcerptSelection
	QueryID   string
}

type ContextQueryAdmission struct {
	Query value.ContextQuery
	Fresh bool // Only the first acknowledged insertion; replay/unknown never start.
}

type ContextQueryBatchAdmission struct {
	Batch value.ContextReadBatch
	Fresh bool
}

// A lookup is private routing/accounting state. Neither it nor Fresh is a peer
// permit. Every mutation independently checks exact acknowledged C-08 lineage,
// accepted C-07 backing, current transaction guards and all original deadlines.
type ContextQueryLedger interface {
	AdmitQuery(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) (ContextQueryAdmission, error)
	LookupQuery(context.Context, identity.Principal, string) (value.ContextQuery, error)
	AdmitQueryPoll(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error
	PermitQuery(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error
	BeginReadBatch(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextQueryWorker, string, value.ContextProjectionAuthority) (ContextQueryBatchAdmission, error)
	ClaimReadBatch(context.Context, value.ContextReadBatch, value.ContextProjectionAuthority) (value.ContextReadStart, error)
	PermitReadBatch(context.Context, value.ContextReadBatch, value.ContextProjectionAuthority) error
	CompleteReadBatch(context.Context, value.ContextReadBatch, ContextProjectionClosed) error
}

// Only initial admission receives this capability. Observing a query/result
// never calls it, including missing, failed, expired or uncertain workers.
type ContextProjectionWorkerAdmission interface {
	AdmitProjectionWorker(context.Context, value.ContextQuery, ContextProjectionRequestOwner) error
}

type ContextProjectionWorkerObservation struct {
	Worker                 value.ContextQueryWorker
	Ready                  bool
	ObservedAt, ValidUntil time.Time
}

// Existing-worker-only read/observation. A missing worker is pending or
// unavailable, never a request to dispatch, replace, repair or reset enrollment.
type ContextProjectionReader interface {
	ObserveProjectionWorker(context.Context, value.ContextQuery, ContextProjectionRequestOwner) (ContextProjectionWorkerObservation, error)
	ReadProjection(context.Context, value.ContextReadStart, ContextProjectionRequestOwner) (ContextProjectionRead, error)
}

// C-14 checks this live request owner and independently validates the exact
// one-use SQL claim/key purpose. A request DTO/certificate alone is insufficient.
type ContextProjectionRequestOwner interface {
	Request() value.ContextQueryRequest
	CheckCurrent(context.Context) (value.ContextProjectionAuthority, error)
}

// C-14 owns this opaque process handle. Close joins the exact private operation;
// errors/EOF/lease expiry never fabricate positive closure. Returning a handle
// alongside an error still transfers its cleanup obligation to C-18.
type ContextProjectionRead interface {
	Projection(context.Context) (value.PodStatusProjection, error)
	CheckCurrent(context.Context) error
	Close(context.Context) error
	ContextProjectionClosed
}

// WithProjectionClosed holds independently verified exact worker/peer/process/
// batch/generation closure while the callback performs only restrictive SQL.
// It is not a caller-set Joined boolean or a serializable completion receipt.
// The SQL facet checks its own active batch and original prepaid cleanup bound;
// no read/key/audit spend is refunded and overdue uncertainty stays represented.
type ContextProjectionClosed interface {
	WithProjectionClosed(context.Context, value.ContextReadBatch, func(context.Context) error) error
}
