package authorization

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-249: individual approval of one sensitive acquisition plan (an
// adHocCapture AccessGrant, REQ-AUT-003, REQ-INV-001) with an optional
// same-human result-access pool. The approved grant itself covers matching
// published artifacts (REQ-INV-002); no per-artifact or per-client grants
// exist. A grant is evaluated at every use; holding one never replaces
// current entitlement, expiry or revocation checks.
const (
	GrantAdHocCapture = "adHocCapture"
	// GrantDefaultLifetime is how long an approved ad hoc grant without
	// result access may start its capture after the decision.
	GrantDefaultLifetime = time.Hour
	// RawQueryDefaultOperations is the query count of a raw grant whose
	// request names none (grant.schema.json limits.maxExecutions).
	RawQueryDefaultOperations = int64(10000)
	// Stored scope and review rows are bounded so one grant row stays a
	// small, indexable record (they are copied into every review page).
	GrantMaxScopeBytes  = 64 << 10
	GrantMaxReviewBytes = 32 << 10
	// GrantMaxRevision: request (1), decision (2), revocation (3).
	GrantMaxRevision = 3
	// GrantDownloadOperation is the one follow-up operation in this release.
	GrantDownloadOperation     = "download_artifact"
	GrantPacketQueryOperation  = "pcap_query"
	GrantSyscallQueryOperation = "syscall_query"
	GrantLogQueryOperation     = "get_logs"
)

var (
	// ErrApprovalRequired: no approved, current grant covers this exact use.
	ErrApprovalRequired = errors.New("approval required")
	// ErrSelfApproval: the reviewer is the requesting human (any client).
	ErrSelfApproval = errors.New("self-approval refused")
	// ErrStepUpRequired: the reviewer lacks a current IdP step-up.
	ErrStepUpRequired = errors.New("step-up authentication required")
	// ErrGrantExpired / ErrGrantRevoked / ErrGrantDenied are final phases.
	ErrGrantExpired = errors.New("grant expired")
	ErrGrantRevoked = errors.New("grant revoked")
	ErrGrantDenied  = errors.New("grant denied")
	// ErrGrantNotPending: the request was already decided or withdrawn.
	ErrGrantNotPending = errors.New("grant request is not pending")
	// ErrGrantScope: capture, execution digest, review digest, action,
	// artifact or operation differ from the approved scope.
	ErrGrantScope = errors.New("grant scope mismatch")
	// ErrGrantPrincipal: the caller is not the grant's requesting human.
	ErrGrantPrincipal = errors.New("grant belongs to another principal")
	// ErrGrantPoolExhausted: the shared result-access pool cannot cover it.
	ErrGrantPoolExhausted = errors.New("grant result-access pool exhausted")
	// ErrNotApprover: no current, undenied action-approver assignment.
	ErrNotApprover = errors.New("not an approver for this target")
	// ErrGrantInvalid: malformed request or stored row.
	ErrGrantInvalid = errors.New("invalid grant")
)

// ApprovalPendingError reports ErrApprovalRequired for a plan whose review
// request GrantID exists (just created or still pending).
type ApprovalPendingError struct{ GrantID string }

func (e ApprovalPendingError) Error() string { return ErrApprovalRequired.Error() + ": " + e.GrantID }
func (e ApprovalPendingError) Unwrap() error { return ErrApprovalRequired }

// GrantPhase is derived from the stored decision, revocation and expiry.
type GrantPhase string

const (
	GrantPending   GrantPhase = "Pending"
	GrantApproved  GrantPhase = "Approved"
	GrantDenied    GrantPhase = "Denied"
	GrantRevoked   GrantPhase = "Revoked"
	GrantExpired   GrantPhase = "Expired"
	GrantExhausted GrantPhase = "Exhausted"
)

// SensitiveReason names why a plan needs individual approval: one action
// and a fixed code (rawBytePredicate, recordingApprovalRequired, ...).
type SensitiveReason struct {
	ActionID, Code string
}

// ResultAccess is the reviewed same-human follow-up instruction
// (REQ-INV-001): selected output actions, operations and one finite
// disclosure pool. It covers every client of the requesting human.
type ResultAccess struct {
	ActionIDs, Operations   []string
	MaxArtifacts            int
	MaxBytes, MaxOperations int64
	// NotAfter is the instruction's absolute end (the grant's expiry); it
	// never starts again when an artifact arrives.
	NotAfter time.Time
}

func sortedUnique(v []string, length int) bool {
	return len(v) >= 1 && identity.Strings(v, len(v), length) && slices.IsSorted(v)
}

// ValidResultOperations is the closed sorted operation set supported by exact output grants.
func ValidResultOperations(operations []string) bool {
	if len(operations) < 1 || len(operations) > 4 {
		return false
	}
	for i, op := range operations {
		if op != GrantDownloadOperation && op != GrantPacketQueryOperation && op != GrantSyscallQueryOperation && op != GrantLogQueryOperation || i > 0 && operations[i-1] >= op {
			return false
		}
	}
	return true
}

func (r ResultAccess) Valid() bool {
	return sortedUnique(r.ActionIDs, 64) && ValidResultOperations(r.Operations) && !r.NotAfter.IsZero() && r.MaxArtifacts >= 1 && r.MaxBytes >= 1 && r.MaxOperations >= 1
}

// GrantDecision is the one recorded approve/deny decision. ACR and
// AuthenticatedAt record the reviewer's step-up when the token carried one;
// step-up is optional (ADR-335 D5).
type GrantDecision struct {
	Approved                   bool
	Approver                   identity.Principal
	Reason, ACR                string
	AuthenticatedAt, DecidedAt time.Time
}

// GrantSpend is the pool's authoritative spent counters; they never
// decrease (uncertain spend stays charged).
type GrantSpend struct {
	Artifacts         int
	Bytes, Operations int64
}

// Grant is one stored adHocCapture AccessGrant. Scope is the frozen
// canonical plan the reviewer approved; ExecutionDigest is its SHA-256.
// ReviewDigest covers kind, capture, execution and result-access digests,
// target, data class, reasons and lifetime: it is what the reviewer
// approves and every use recomputes.
type Grant struct {
	policyStartWitness                                *policyGrantStartWitness
	ID, RootID, Kind                                  string
	PreviewID, CaptureID                              string
	Target                                            Target
	ExecutionDigest, ResultAccessDigest, ReviewDigest artifact.Digest
	DataClass                                         string
	Reasons                                           []SensitiveReason
	Scope, Review                                     []byte
	Requester                                         identity.Principal
	RequestedAt                                       time.Time
	Lifetime                                          time.Duration
	ResultAccess                                      *ResultAccess
	RawQuery                                          *RawQueryScope `json:",omitempty"`
	Policy                                            *PolicyGrantScope
	// PolicyNotAfter is the monotonic accepted-settings overlay, also for pending requests.
	PolicyNotAfter time.Time
	Decision       *GrantDecision
	ExpiresAt      time.Time
	RevokedAt      time.Time
	Revoker        identity.Principal
	Revision       int64
	Spent          GrantSpend
	PolicySpend    PolicyGrantSpend `json:",omitzero"`
	// Submission lets approval submit the reviewed request (ADR-335 D5).
	Submission *GrantSubmission `json:"-"`
}

// GrantSubmission is what approval needs to submit an ad hoc request as its
// requester: the reviewed request_capture input and the requester's verified
// groups, scopes and identity policy revision. Until is the end of the
// requester's authentication. These groups are never used after Until.
type GrantSubmission struct {
	Request        []byte
	Groups, Scopes []string
	Policy         identity.Revision
	Until          time.Time
}

func validDataClass(c string) bool { return c == "metadata" || c == "extract" || c == "raw" }

func (g Grant) Valid() bool {
	if !UUID(g.ID) || !UUID(g.RootID) || !g.validKindScope() ||
		g.ExecutionDigest == (artifact.Digest{}) || g.ReviewDigest == (artifact.Digest{}) || !validDataClass(g.DataClass) ||
		len(g.Reasons) < 1 || len(g.Scope) < 2 || len(g.Scope) > GrantMaxScopeBytes || len(g.Review) < 2 || len(g.Review) > GrantReviewBytesLimit(g.Kind) ||
		!g.Requester.Valid() || g.RequestedAt.IsZero() ||
		g.Revision < 1 || g.Revision > GrantMaxRevision {
		return false
	}
	if (g.ResultAccess == nil) != (g.ResultAccessDigest == (artifact.Digest{})) || g.ResultAccess != nil && (!g.ResultAccess.Valid() || !g.ResultAccess.NotAfter.After(g.RequestedAt)) {
		return false
	}
	for _, r := range g.Reasons {
		if !identity.Text(r.ActionID, 64) || !identity.Text(r.Code, 64) {
			return false
		}
	}
	if d := g.Decision; d != nil {
		// Self-approval is refused by issuer and subject, across clients. A
		// later lower policy maximum may end the period before the decision.
		if !d.Approver.Valid() || d.Approver.Kind != identity.Human || sameHuman(d.Approver, g.Requester) || !identity.Text(d.Reason, 512) || d.DecidedAt.Before(g.RequestedAt) || g.Kind != GrantPolicy && g.lapsed(d.DecidedAt) {
			return false
		}
		if d.Approved != !g.ExpiresAt.IsZero() || d.Approved && !g.validApprovedExpiry(d.DecidedAt) || d.AuthenticatedAt.After(d.DecidedAt) {
			return false
		}
	} else if !g.ExpiresAt.IsZero() {
		return false
	}
	if !g.RevokedAt.IsZero() && !g.Revoker.Valid() {
		return false
	}
	if g.Kind == GrantPolicy && (!g.PolicySpend.valid(g.Policy) || (g.Decision == nil || !g.Decision.Approved) && g.PolicySpend != (PolicyGrantSpend{}) || g.Spent != (GrantSpend{})) {
		return false
	}
	if g.Kind != GrantPolicy && g.PolicySpend != (PolicyGrantSpend{}) {
		return false
	}
	return g.Spent.Artifacts >= 0 && g.Spent.Bytes >= 0 && g.Spent.Operations >= 0
}

// expiryAt is the expiry an approval at decided would set. Result access,
// raw queries and policy grants end at their own absolute bound; an ad hoc
// grant without result access keeps its pinned lifetime from the decision.
func (g Grant) expiryAt(decided time.Time) time.Time {
	if until := g.PendingUntil(); !until.IsZero() {
		return until
	}
	return decided.Add(g.Lifetime)
}

// PendingUntil is the absolute bound a review stays decidable until (and an
// approval's expiry): the policy period, the raw or result-access notAfter.
// Zero means the request stays decidable until it is decided or cancelled.
func (g Grant) PendingUntil() time.Time {
	switch {
	case g.Kind == GrantPolicy:
		return g.PolicyNotAfter
	case g.RawQuery != nil:
		return g.RawQuery.NotAfter
	case g.ResultAccess != nil:
		return g.ResultAccess.NotAfter
	}
	return time.Time{}
}

func (g Grant) lapsed(now time.Time) bool {
	until := g.PendingUntil()
	return !until.IsZero() && !now.Before(until)
}

func sameHuman(a, b identity.Principal) bool { return a.Issuer == b.Issuer && a.Subject == b.Subject }

// Phase is the grant's current phase. Revocation wins over every other
// state; a pending request lapses only at its absolute bound (PendingUntil).
func (g Grant) Phase(now time.Time) GrantPhase {
	switch {
	case !g.RevokedAt.IsZero():
		return GrantRevoked
	case g.Decision == nil && g.lapsed(now):
		return GrantExpired
	case g.Decision == nil:
		return GrantPending
	case !g.Decision.Approved:
		return GrantDenied
	case !now.Before(g.ExpiresAt):
		return GrantExpired
	case g.Kind == GrantPolicy && g.PolicySpend.Exhausted(g.Policy):
		return GrantExhausted
	}
	return GrantApproved
}

func phaseError(p GrantPhase) error {
	switch p {
	case GrantApproved:
		return nil
	case GrantRevoked:
		return ErrGrantRevoked
	case GrantDenied:
		return ErrGrantDenied
	case GrantExpired:
		return ErrGrantExpired
	case GrantExhausted:
		return ErrPolicyGrantBudgetExhausted
	}
	return ErrApprovalRequired
}

// CheckDecision evaluates one reviewer's approve or deny decision. The
// reviewer must be a different human (issuer and subject, whatever the
// client), hold a current undenied action-approver assignment for the target
// (eligible, from ScopeEligibility with ApproveAction) and, to approve, a
// current IdP step-up. Denial only restricts, so it needs no step-up.
func CheckDecision(g Grant, reviewer identity.Identity, eligible Result, approve bool, now time.Time) error {
	if !g.Valid() {
		return ErrGrantInvalid
	}
	if g.Phase(now) != GrantPending {
		return ErrGrantNotPending
	}
	if !reviewer.Valid(now) || reviewer.Principal.Kind != identity.Human {
		return ErrNotApprover
	}
	if sameHuman(reviewer.Principal, g.Requester) {
		return ErrSelfApproval
	}
	if !eligible.Eligible || eligible.Principal != reviewer.Principal || !now.Before(eligible.ValidUntil) {
		return ErrNotApprover
	}
	if approve && !reviewer.SteppedUp(now) {
		return ErrStepUpRequired
	}
	if approve && !now.Before(g.expiryAt(now)) {
		// Approving now would create an already expired grant.
		return ErrGrantExpired
	}
	return nil
}

// CheckCaptureUse decides whether the grant covers starting the exact
// reviewed plan: same capture identity, execution digest and review digest,
// requested by the calling human through the requesting client, approved,
// unrevoked and unexpired. Current collection eligibility is checked by the
// caller with the same projection; this rule never replaces it.
func CheckCaptureUse(g Grant, caller identity.Identity, captureID string, execution, review artifact.Digest, now time.Time) error {
	if !g.Valid() {
		return ErrGrantInvalid
	}
	if err := phaseError(g.Phase(now)); err != nil {
		return err
	}
	if !caller.Valid(now) || !sameHuman(caller.Principal, g.Requester) {
		return ErrGrantPrincipal
	}
	if g.Kind != GrantAdHocCapture || g.CaptureID != captureID || g.ExecutionDigest != execution || g.ReviewDigest != review {
		return ErrGrantScope
	}
	return nil
}

// VerifiedOutput is one committed, independently verified artifact of the
// approved capture (C-14 publication). Only these may become child targets.
type VerifiedOutput struct {
	CaptureID, ActionID, ArtifactID string
	ExecutionDigest, ArtifactDigest artifact.Digest
	Target                          Target
}

func (o VerifiedOutput) Valid() bool {
	return UUID(o.CaptureID) && identity.Text(o.ActionID, 64) && UUID(o.ArtifactID) && o.ExecutionDigest != (artifact.Digest{}) && o.ArtifactDigest != (artifact.Digest{}) && o.Target.Valid()
}

// GrantOutputGroup is an immutable association read from the accepted group
// and exact published member. It supplies no current permission or recovery.
// SQL revalidates the same association under the existing transaction locks.
type GrantOutputGroup struct {
	RootID, ParentCaptureID, CaptureID, ArtifactID, ActionID string
	ParentExecutionDigest, ExecutionDigest, ArtifactDigest   artifact.Digest
	ChildIndex, ChildCount                                   int
}

func (a GrantOutputGroup) Valid() bool {
	return UUID(a.RootID) && UUID(a.ParentCaptureID) && UUID(a.CaptureID) && a.ParentCaptureID != a.CaptureID && UUID(a.ArtifactID) && identity.Text(a.ActionID, 64) && a.ParentExecutionDigest != (artifact.Digest{}) && a.ExecutionDigest != (artifact.Digest{}) && a.ArtifactDigest != (artifact.Digest{}) && a.ChildCount >= 2 && a.ChildCount <= 16 && a.ChildIndex >= 0 && a.ChildIndex < a.ChildCount
}
func (a GrantOutputGroup) Matches(g Grant, o VerifiedOutput) bool {
	return a.Valid() && g.Kind == GrantAdHocCapture && a.RootID == g.RootID && a.ParentCaptureID == g.CaptureID && a.ParentExecutionDigest == g.ExecutionDigest && a.CaptureID == o.CaptureID && a.ExecutionDigest == o.ExecutionDigest && a.ArtifactID == o.ArtifactID && a.ArtifactDigest == o.ArtifactDigest && a.ActionID == o.ActionID
}
func approvedOutput(g Grant, o VerifiedOutput, group *GrantOutputGroup) bool {
	if group == nil {
		return o.CaptureID == g.CaptureID && o.ExecutionDigest == g.ExecutionDigest
	}
	return group.Matches(g, o)
}

// GrantArtifact records one distinct artifact used under a grant: the pool's
// maxArtifacts counts these rows. It is not a grant; it carries no client and
// no authority of its own.
type GrantArtifact struct {
	ID, ParentID string
	Output       VerifiedOutput
	// Group is resolved locally from protected SQL, never accepted from a wire reply.
	Group     *GrantOutputGroup `json:"-"`
	CreatedAt time.Time
}

func (c GrantArtifact) Valid() bool {
	return UUID(c.ID) && UUID(c.ParentID) && c.Output.Valid() && !c.CreatedAt.IsZero()
}

// CheckRegister decides whether output may be registered under the grant.
// registered reports whether the artifact already counts toward
// MaxArtifacts (a repeated use or duplicate commit delivery).
func CheckRegister(g Grant, output VerifiedOutput, registered bool, now time.Time, group *GrantOutputGroup) error {
	if !g.Valid() || !output.Valid() {
		return ErrGrantInvalid
	}
	if err := phaseError(g.Phase(now)); err != nil {
		return err
	}
	if g.Kind == GrantRawQuery {
		if !g.RawQuery.covers(output, now) {
			return ErrGrantScope
		}
		if !registered && g.Spent.Artifacts >= len(g.RawQuery.Artifacts) {
			return ErrGrantPoolExhausted
		}
		return nil
	}
	r := g.ResultAccess
	if r == nil || !approvedOutput(g, output, group) || output.Target != g.Target || !slices.Contains(r.ActionIDs, output.ActionID) {
		return ErrGrantScope
	}
	if !registered && g.Spent.Artifacts >= r.MaxArtifacts {
		return ErrGrantPoolExhausted
	}
	return nil
}

// GrantUse is one requested follow-up disclosure charged to the pool.
type GrantUse struct {
	Operation         string
	Bytes, Operations int64
}

// CheckResultUse decides one use of a registered artifact by the calling
// identity: the requesting human on any client, an allowed operation and a
// current grant. The pool is reserved atomically by the ledger (PoolCovers
// states the rule) before delivery and never refunded; current ordinary
// entitlement is the caller's check.
func CheckResultUse(g Grant, c GrantArtifact, caller identity.Identity, operation string, now time.Time) error {
	if !g.Valid() || !c.Valid() || c.ParentID != g.ID {
		return ErrGrantInvalid
	}
	if err := phaseError(g.Phase(now)); err != nil {
		return err
	}
	if !caller.Valid(now) || !sameHuman(caller.Principal, g.Requester) || caller.Principal.Kind != identity.Human {
		return ErrGrantPrincipal
	}
	if g.Kind == GrantRawQuery {
		if !slices.Contains(g.RawQuery.Operations, operation) || !g.RawQuery.covers(c.Output, now) {
			return ErrGrantScope
		}
		return nil
	}
	r := g.ResultAccess
	if r == nil || !slices.Contains(r.Operations, operation) || !approvedOutput(g, c.Output, c.Group) {
		return ErrGrantScope
	}
	return nil
}

// PoolCovers reports whether the pool can still reserve use.
func PoolCovers(g Grant, use GrantUse) bool {
	var bytes, operations int64
	switch {
	case g.Kind == GrantRawQuery && g.RawQuery != nil:
		bytes, operations = g.RawQuery.MaxBytes, g.RawQuery.MaxOperations
	case g.ResultAccess != nil:
		bytes, operations = g.ResultAccess.MaxBytes, g.ResultAccess.MaxOperations
	default:
		return false
	}
	return use.Bytes >= 0 && use.Operations >= 0 && (use.Bytes > 0 || use.Operations > 0) &&
		g.Spent.Bytes >= 0 && g.Spent.Bytes <= bytes && g.Spent.Operations >= 0 && g.Spent.Operations <= operations &&
		use.Bytes <= bytes-g.Spent.Bytes && use.Operations <= operations-g.Spent.Operations
}

// CanRevoke reports whether actor may revoke: the requesting human (any
// client) or a current approver (eligible ApproveAction). Revocation only
// restricts access, so it needs no step-up.
func CanRevoke(g Grant, actor identity.Identity, approver Result, now time.Time) bool {
	if !actor.Valid(now) || actor.Principal.Kind != identity.Human || !g.RevokedAt.IsZero() {
		return false
	}
	return (g.Kind == GrantAdHocCapture || g.Kind == GrantRawQuery) && sameHuman(actor.Principal, g.Requester) || approver.Eligible && approver.Principal == actor.Principal && now.Before(approver.ValidUntil)
}

// validKindScope keeps policy team authority disjoint from personal capture
// authority. Policy fields may never be smuggled into an old ad hoc scope.
func (g Grant) validKindScope() bool {
	switch g.Kind {
	case GrantRawQuery:
		return g.validRawQuery()
	case GrantAdHocCapture:
		return g.RawQuery == nil && g.Policy == nil && g.PolicyNotAfter.IsZero() && g.Requester.Kind == identity.Human && UUID(g.PreviewID) && UUID(g.CaptureID) && g.Target.Valid() && g.Lifetime >= time.Minute
	case GrantPolicy:
		_, _, executorRequester := PolicyExecutor(g.Requester)
		return g.RawQuery == nil && !executorRequester && g.Policy != nil && g.policyStartWitnessValid() && g.Policy.valid(g.RequestedAt) && g.PolicyNotAfter.After(g.RequestedAt) && !g.PolicyNotAfter.After(identity.Earlier(g.RequestedAt.Add(g.Lifetime), g.Policy.Authority.NotAfter)) && g.ExecutionDigest == g.Policy.Authority.ScopeDigest && g.PreviewID == "" && g.CaptureID == "" && g.Target == (Target{}) && g.ResultAccess == nil && g.ResultAccessDigest == (artifact.Digest{}) && g.Lifetime >= time.Second && g.Lifetime <= g.Policy.ApprovalMaxAge
	default:
		return false
	}
}

// Accepted lower policy maxima shorten PolicyNotAfter under SQL locks; raising
// a maximum cannot lengthen the persisted expiry.
func (g Grant) validApprovedExpiry(decided time.Time) bool {
	return g.ExpiresAt.Equal(g.expiryAt(decided))
}

// GrantReviewBytesLimit gives the existing-artifact review room for its exact
// target/file rows while keeping the collection review limit.
func GrantReviewBytesLimit(kind string) int {
	if kind == GrantRawQuery {
		return 128 << 10
	}
	return GrantMaxReviewBytes
}
