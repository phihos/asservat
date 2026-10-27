package authorization

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-249 (S-04 increment 12): individual approval of one sensitive
// acquisition plan (an adHocCapture AccessGrant, REQ-AUT-003, REQ-INV-001)
// with an optional same-human result-access pool and exact child grants
// (REQ-INV-002). A grant is evaluated at every use; holding one never
// replaces current entitlement, client, expiry or revocation checks.
const (
	GrantAdHocCapture = "adHocCapture"
	// GrantDefaultLifetime is the spec's ad hoc default; GrantMaxLifetime is
	// the raw-query maximum, which also bounds the combined follow-up access.
	GrantDefaultLifetime = time.Hour
	GrantMaxLifetime     = 8 * time.Hour
	// GrantReviewWindow bounds how long a request stays reviewable.
	GrantReviewWindow = time.Hour
	// Result-access bounds (installation constants, not configuration).
	GrantMaxResultActions    = 16
	GrantMaxResultClients    = 4
	GrantMaxResultArtifacts  = 64
	GrantMaxResultBytes      = int64(256) << 30
	GrantMaxResultOperations = int64(10000)
	GrantMaxReasons          = 16
	GrantMaxScopeBytes       = 64 << 10
	GrantMaxReviewBytes      = 32 << 10
	// GrantMaxRevision: request (1), decision (2), revocation (3).
	GrantMaxRevision = 3
	// GrantDownloadOperation is the one follow-up operation in this release.
	GrantDownloadOperation = "download_artifact"
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
	// artifact, operation or client differ from the approved scope.
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
	GrantPending  GrantPhase = "Pending"
	GrantApproved GrantPhase = "Approved"
	GrantDenied   GrantPhase = "Denied"
	GrantRevoked  GrantPhase = "Revoked"
	GrantExpired  GrantPhase = "Expired"
)

// SensitiveReason names why a plan needs individual approval: one action
// and a fixed code (rawBytePredicate, recordingApprovalRequired, ...).
type SensitiveReason struct {
	ActionID, Code string
}

// ResultAccess is the reviewed same-human follow-up instruction
// (REQ-INV-001): selected output actions, operations, explicitly selected
// client IDs and one finite disclosure pool shared by every child.
type ResultAccess struct {
	ActionIDs, Operations, ClientIDs []string
	MaxArtifacts                     int
	MaxBytes, MaxOperations          int64
	// NotAfter is the instruction's absolute end; it only shortens the
	// grant's expiry and never starts again when an artifact arrives.
	NotAfter time.Time
}

func sortedUnique(v []string, minimum, maximum, length int) bool {
	return len(v) >= minimum && identity.Strings(v, maximum, length) && slices.IsSorted(v)
}

func (r ResultAccess) Valid() bool {
	if !sortedUnique(r.ActionIDs, 1, GrantMaxResultActions, 64) || !sortedUnique(r.ClientIDs, 1, GrantMaxResultClients, 256) || !slices.Equal(r.Operations, []string{GrantDownloadOperation}) {
		return false
	}
	return !r.NotAfter.IsZero() && r.MaxArtifacts >= 1 && r.MaxArtifacts <= GrantMaxResultArtifacts && r.MaxBytes >= 1 && r.MaxBytes <= GrantMaxResultBytes && r.MaxOperations >= 1 && r.MaxOperations <= GrantMaxResultOperations
}

// GrantDecision is the one recorded approve/deny decision. ACR and
// AuthenticatedAt are the reviewer's verified authentication context.
type GrantDecision struct {
	Approved                   bool
	Approver                   identity.Principal
	Reason, ACR                string
	AuthenticatedAt, DecidedAt time.Time
}

// GrantSpend is the shared pool's authoritative spent counters; they never
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
	ID, RootID, Kind                                  string
	PreviewID, CaptureID                              string
	Target                                            Target
	ExecutionDigest, ResultAccessDigest, ReviewDigest artifact.Digest
	DataClass                                         string
	Reasons                                           []SensitiveReason
	Scope, Review                                     []byte
	Requester                                         identity.Principal
	RequestedAt, ReviewUntil                          time.Time
	Lifetime                                          time.Duration
	ResultAccess                                      *ResultAccess
	Decision                                          *GrantDecision
	ExpiresAt                                         time.Time
	RevokedAt                                         time.Time
	Revoker                                           identity.Principal
	Revision                                          int64
	Spent                                             GrantSpend
}

func validDataClass(c string) bool { return c == "metadata" || c == "extract" || c == "raw" }

func (g Grant) Valid() bool {
	if !UUID(g.ID) || !UUID(g.RootID) || g.Kind != GrantAdHocCapture || !UUID(g.PreviewID) || !UUID(g.CaptureID) || !g.Target.Valid() ||
		g.ExecutionDigest == (artifact.Digest{}) || g.ReviewDigest == (artifact.Digest{}) || !validDataClass(g.DataClass) ||
		len(g.Reasons) < 1 || len(g.Reasons) > GrantMaxReasons || len(g.Scope) < 2 || len(g.Scope) > GrantMaxScopeBytes || len(g.Review) < 2 || len(g.Review) > GrantMaxReviewBytes ||
		!g.Requester.Valid() || g.Requester.Kind != identity.Human ||
		g.RequestedAt.IsZero() || !g.ReviewUntil.After(g.RequestedAt) || g.ReviewUntil.Sub(g.RequestedAt) > GrantReviewWindow ||
		g.Lifetime < time.Minute || g.Lifetime > GrantMaxLifetime || g.Revision < 1 || g.Revision > GrantMaxRevision {
		return false
	}
	if (g.ResultAccess == nil) != (g.ResultAccessDigest == (artifact.Digest{})) || g.ResultAccess != nil && (!g.ResultAccess.Valid() || !g.ResultAccess.NotAfter.After(g.RequestedAt) || g.ResultAccess.NotAfter.After(g.RequestedAt.Add(GrantMaxLifetime))) {
		return false
	}
	for _, r := range g.Reasons {
		if !identity.Text(r.ActionID, 64) || !identity.Text(r.Code, 64) {
			return false
		}
	}
	if d := g.Decision; d != nil {
		// Self-approval is refused by issuer and subject, across clients.
		if !d.Approver.Valid() || d.Approver.Kind != identity.Human || sameHuman(d.Approver, g.Requester) || !identity.Text(d.Reason, 512) || d.DecidedAt.Before(g.RequestedAt) || d.DecidedAt.After(g.ReviewUntil) {
			return false
		}
		if d.Approved != !g.ExpiresAt.IsZero() || d.Approved && !g.ExpiresAt.Equal(g.expiryAt(d.DecidedAt)) || d.Approved && (d.ACR == "" || d.AuthenticatedAt.IsZero() || d.AuthenticatedAt.After(d.DecidedAt)) {
			return false
		}
	} else if !g.ExpiresAt.IsZero() {
		return false
	}
	if !g.RevokedAt.IsZero() && !g.Revoker.Valid() {
		return false
	}
	return g.Spent.Artifacts >= 0 && g.Spent.Bytes >= 0 && g.Spent.Operations >= 0
}

// expiryAt is the expiry an approval at decided would set: the pinned
// lifetime from the decision, never past the result-access NotAfter.
func (g Grant) expiryAt(decided time.Time) time.Time {
	end := decided.Add(g.Lifetime)
	if g.ResultAccess != nil {
		end = identity.Earlier(end, g.ResultAccess.NotAfter)
	}
	return end
}

func sameHuman(a, b identity.Principal) bool { return a.Issuer == b.Issuer && a.Subject == b.Subject }

// Phase is the grant's current phase. Revocation wins over every other
// state; a pending request lapses at ReviewUntil.
func (g Grant) Phase(now time.Time) GrantPhase {
	switch {
	case !g.RevokedAt.IsZero():
		return GrantRevoked
	case g.Decision == nil && !now.Before(g.ReviewUntil):
		return GrantExpired
	case g.Decision == nil:
		return GrantPending
	case !g.Decision.Approved:
		return GrantDenied
	case !now.Before(g.ExpiresAt):
		return GrantExpired
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
	if !caller.Valid(now) || caller.Principal != g.Requester {
		return ErrGrantPrincipal
	}
	if g.CaptureID != captureID || g.ExecutionDigest != execution || g.ReviewDigest != review {
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

// GrantChild is one exact child grant: an existing artifact digest, one
// approved client of the original human and the parent's operations,
// inheriting the parent's decision provenance, expiry and pool.
type GrantChild struct {
	ID, ParentID, ClientID string
	Output                 VerifiedOutput
	CreatedAt              time.Time
}

func (c GrantChild) Valid() bool {
	return UUID(c.ID) && UUID(c.ParentID) && identity.Text(c.ClientID, 256) && c.Output.Valid() && !c.CreatedAt.IsZero()
}

// CheckMaterialize decides whether the parent may register output for
// clientID. registered reports whether the artifact already counts toward
// MaxArtifacts (another client's child or a duplicate commit delivery).
func CheckMaterialize(g Grant, output VerifiedOutput, clientID string, registered bool, now time.Time) error {
	if !g.Valid() || !output.Valid() {
		return ErrGrantInvalid
	}
	if err := phaseError(g.Phase(now)); err != nil {
		return err
	}
	r := g.ResultAccess
	if r == nil || output.CaptureID != g.CaptureID || output.ExecutionDigest != g.ExecutionDigest || output.Target != g.Target || !slices.Contains(r.ActionIDs, output.ActionID) || !slices.Contains(r.ClientIDs, clientID) {
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

// CheckResultUse decides one child use by the calling identity: the
// requesting human through the child's client, an allowed operation and a
// current parent. The shared pool is reserved atomically by the ledger
// (PoolCovers states the rule) before delivery and never refunded; current
// ordinary entitlement is the caller's check.
func CheckResultUse(g Grant, c GrantChild, caller identity.Identity, operation string, now time.Time) error {
	if !g.Valid() || !c.Valid() || c.ParentID != g.ID {
		return ErrGrantInvalid
	}
	if err := phaseError(g.Phase(now)); err != nil {
		return err
	}
	if !caller.Valid(now) || !sameHuman(caller.Principal, g.Requester) || caller.Principal.Kind != identity.Human || caller.Principal.ClientID != c.ClientID {
		return ErrGrantPrincipal
	}
	r := g.ResultAccess
	if r == nil || !slices.Contains(r.Operations, operation) || !slices.Contains(r.ClientIDs, c.ClientID) || c.Output.CaptureID != g.CaptureID || c.Output.ExecutionDigest != g.ExecutionDigest {
		return ErrGrantScope
	}
	return nil
}

// PoolCovers reports whether the shared pool can still reserve use.
func PoolCovers(g Grant, use GrantUse) bool {
	r := g.ResultAccess
	return r != nil && use.Bytes >= 0 && use.Operations >= 0 && use.Bytes+use.Operations > 0 && g.Spent.Bytes+use.Bytes <= r.MaxBytes && g.Spent.Operations+use.Operations <= r.MaxOperations
}

// CanRevoke reports whether actor may revoke: the requesting human (any
// client) or a current approver (eligible ApproveAction). Revocation only
// restricts access, so it needs no step-up.
func CanRevoke(g Grant, actor identity.Identity, approver Result, now time.Time) bool {
	if !actor.Valid(now) || actor.Principal.Kind != identity.Human || !g.RevokedAt.IsZero() {
		return false
	}
	return sameHuman(actor.Principal, g.Requester) || approver.Eligible && approver.Principal == actor.Principal && now.Before(approver.ValidUntil)
}
