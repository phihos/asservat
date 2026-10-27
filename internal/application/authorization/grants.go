package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-249: C-03 owns individual (adHocCapture) AccessGrants, their review,
// revocation, exact child grants and the shared result-access pool. It grants
// nothing by itself: every use re-evaluates the stored grant, the caller and
// the current permission projection.

// ErrGrantUnavailable: a dependency (store, recovery, projection) failed.
var ErrGrantUnavailable = errors.New("grant service unavailable")

// ErrGrantConflict: an idempotency key or capture already names another request.
var ErrGrantConflict = errors.New("grant request conflict")

// ErrGrantNotFound: no grant with this ID is visible to the caller.
var ErrGrantNotFound = errors.New("grant not found")

// GrantReviewAction is one action of the reviewed plan, as the approval
// page shows it.
type GrantReviewAction struct {
	ActionID, Kind, ExecutionMode, Before, After, Filter, RingMaxAge string
	FilterDigest                                                     artifact.Digest
	FilterInstructions                                               int
	MaxBytes, RingMaxBytes                                           int64
	Sensitive                                                        []string
}

// GrantObservationLimits are the plan's REQ-AUT-006 limits.
type GrantObservationLimits struct {
	MaxSessionSeconds, MaxObservedBytes, MaxBytesPerSecond, MaxConcurrentSessions int64
}

// GrantReview is the bounded review summary stored with the request. The
// frozen Scope remains the authority; this is its presentation.
type GrantReview struct {
	Namespace, WorkloadKind, WorkloadName, PodName string
	Actions                                        []GrantReviewAction
	ObservationLimits                              *GrantObservationLimits `json:",omitempty"`
	Deadline                                       time.Time
}

// GrantRequestInput is one approval request prepared by the capture service
// from a current, persisted preview it read for the calling principal.
type GrantRequestInput struct {
	PreviewID, CaptureID string
	Actor                identity.Principal
	Target               value.Target
	Scope                []byte
	ExecutionDigest      artifact.Digest
	DataClass            string
	Reasons              []value.SensitiveReason
	Review               GrantReview
	Lifetime             time.Duration
	ResultAccess         *value.ResultAccess
	IdempotencyKey       string
}

// StoredGrantRequest is what the store inserts; the review window and
// request time come from the database clock.
type StoredGrantRequest struct {
	Grant          value.Grant
	IdempotencyKey string
	RequestDigest  artifact.Digest
}

// GrantDecisionInput is one recorded decision after every current check.
type GrantDecisionInput struct {
	GrantID        string
	Approve        bool
	Approver       identity.Principal
	Reason         string
	ACR            string
	AuthTime       time.Time
	IdempotencyKey string
}

// GrantRevocationInput revokes one grant at its expected revision.
type GrantRevocationInput struct {
	GrantID          string
	Revoker          identity.Principal
	ExpectedRevision int64
	IdempotencyKey   string
}

// GrantChildRequest registers one verified output for one approved client.
type GrantChildRequest struct {
	ChildID, ParentID, ClientID string
	Output                      value.VerifiedOutput
}

// GrantUseRequest reserves one follow-up use (an operation ID, idempotent).
type GrantUseRequest struct {
	UseID, ParentID, ChildID string
	Use                      value.GrantUse
}

// GrantStore is the SQL grant ledger (Migration 00097). Mutations run under
// the current recovery fence; a replayed key returns the stored row and
// replay=true. The store re-checks decision, revocation, expiry, pool and
// self-approval in SQL; the service's checks come first.
type GrantStore interface {
	RequestGrant(context.Context, StoredGrantRequest, artifact.RecoveryProof) (value.Grant, bool, error)
	Grant(ctx context.Context, grantID string) (value.Grant, error)
	GrantByCapture(ctx context.Context, captureID string) (value.Grant, error)
	PendingGrants(ctx context.Context, limit int) ([]value.Grant, error)
	RequestedGrants(ctx context.Context, requester identity.Principal, limit int) ([]value.Grant, error)
	DecideGrant(context.Context, GrantDecisionInput, artifact.RecoveryProof) (value.Grant, bool, error)
	RevokeGrant(context.Context, GrantRevocationInput, artifact.RecoveryProof) (value.Grant, bool, error)
	MaterializeGrantChild(context.Context, GrantChildRequest, artifact.RecoveryProof) (value.GrantChild, bool, error)
	GrantChild(ctx context.Context, childID string) (value.GrantChild, error)
	ReserveGrantUse(context.Context, GrantUseRequest, artifact.RecoveryProof) (value.Grant, bool, error)
}

// GrantRecovery is the current recovery fence.
type GrantRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// GrantService implements the grant operations. Approval needs a distinct
// human with a current, undenied action-approver assignment for the exact
// target and a current IdP step-up; nobody can approve their own request.
type GrantService struct {
	RootID, InstallationID string
	Permissions            ProjectionReader
	Store                  GrantStore
	Recovery               GrantRecovery
	NewID                  func() string
	Now                    func() time.Time
}

// GrantView is one grant as one caller may see it now.
type GrantView struct {
	Grant  value.Grant
	Phase  value.GrantPhase
	Review GrantReview
	// Approver reports that the caller may decide or revoke it now.
	Approver bool
	// CanResume is an advisory hint for the current original requester/client.
	// Capture admission remains authoritative.
	CanResume bool
	// CanResolve permits offering passive lookup/closure, never a new start.
	CanResolve bool
}

func (s GrantService) ready() bool {
	return s.Permissions != nil && s.Store != nil && s.Recovery != nil && s.NewID != nil && s.Now != nil && value.UUID(s.RootID) && value.UUID(s.InstallationID)
}

func (s GrantService) human(ctx context.Context, current identities.CurrentIdentity, scopes ...string) (identity.Identity, error) {
	if current == nil {
		return identity.Identity{}, identity.ErrDenied
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) || i.Principal.Kind != identity.Human || !slices.Contains(i.Scopes, "evidence:read") {
		return identity.Identity{}, identity.ErrDenied
	}
	for _, scope := range scopes {
		if !slices.Contains(i.Scopes, scope) {
			return identity.Identity{}, identity.ErrDenied
		}
	}
	return i, nil
}

func (s GrantService) recovery(ctx context.Context) (artifact.RecoveryProof, error) {
	r, err := s.Recovery.RecoveryState(ctx)
	if err != nil || r.InstallationID != s.InstallationID || !r.Valid(s.Now()) {
		return artifact.RecoveryProof{}, ErrGrantUnavailable
	}
	return r, nil
}

func (s GrantService) final(ctx context.Context, current identities.CurrentIdentity, i identity.Identity) error {
	final, err := current.ResolveIdentity(ctx)
	if err != nil || !final.Valid(s.Now()) || final.Principal != i.Principal || ctx.Err() != nil {
		return identity.ErrDenied
	}
	return nil
}

// NormalizeResultAccess sorts the instruction's sets and truncates NotAfter
// to the stored microsecond precision, so equal instructions have one digest.
func NormalizeResultAccess(r value.ResultAccess) value.ResultAccess {
	r.ActionIDs, r.ClientIDs, r.Operations = slices.Sorted(slices.Values(r.ActionIDs)), slices.Sorted(slices.Values(r.ClientIDs)), slices.Sorted(slices.Values(r.Operations))
	r.NotAfter = r.NotAfter.UTC().Truncate(time.Microsecond)
	return r
}

// ResultAccessDigest is the canonical REQ-INV-001 digest over
// {captureUID, executionDigest, resultAccess}.
func ResultAccessDigest(captureID string, execution artifact.Digest, r value.ResultAccess) artifact.Digest {
	b, _ := json.Marshal(struct {
		CaptureUID      string
		ExecutionDigest artifact.Digest
		ResultAccess    value.ResultAccess
	}{captureID, execution, r})
	return sha256.Sum256(b)
}

// ReviewDigest is what the reviewer approves: kind, capture, execution and
// result-access digests, target, data class, reasons, lifetime and the
// review summary. Every use recomputes it from the stored row.
func ReviewDigest(g value.Grant, review []byte) artifact.Digest {
	b, _ := json.Marshal(struct {
		Kind, PreviewID, CaptureID          string
		Target                              value.Target
		ExecutionDigest, ResultAccessDigest artifact.Digest
		DataClass                           string
		Reasons                             []value.SensitiveReason
		LifetimeSeconds                     int64
		Review                              json.RawMessage
	}{g.Kind, g.PreviewID, g.CaptureID, g.Target, g.ExecutionDigest, g.ResultAccessDigest, g.DataClass, g.Reasons, int64(g.Lifetime / time.Second), review})
	return sha256.Sum256(b)
}

func (s GrantService) collector(ctx context.Context, i identity.Identity, t value.Target, op value.Operation) (value.Result, error) {
	p, err := s.Permissions.Permissions(ctx, t)
	if err != nil {
		return value.Result{}, ErrGrantUnavailable
	}
	return value.ScopeEligibility(i, p, op, t, s.Now()), nil
}

// Request records a pending approval request for one current preview. The
// caller must be the preview's actor with current whole-pod collection
// eligibility. One capture identity has at most one request; a retry with
// the same key and content returns it.
func (s GrantService) Request(ctx context.Context, current identities.CurrentIdentity, in GrantRequestInput) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() {
		return zero, false, ErrGrantUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current, "evidence:capture")
	if err != nil {
		return zero, false, err
	}
	if i.Principal != in.Actor || !identity.Text(in.IdempotencyKey, 128) || in.Lifetime == 0 {
		return zero, false, value.ErrGrantInvalid
	}
	review, err := json.Marshal(in.Review)
	if err != nil || len(review) > value.GrantMaxReviewBytes {
		return zero, false, value.ErrGrantInvalid
	}
	g := value.Grant{Review: review, ID: s.NewID(), RootID: s.RootID, Kind: value.GrantAdHocCapture, PreviewID: in.PreviewID, CaptureID: in.CaptureID, Target: in.Target,
		ExecutionDigest: in.ExecutionDigest, DataClass: in.DataClass, Reasons: slices.Clone(in.Reasons), Scope: slices.Clone(in.Scope), Requester: i.Principal,
		Lifetime: in.Lifetime, Revision: 1}
	if sha256.Sum256(in.Scope) != in.ExecutionDigest {
		return zero, false, value.ErrGrantInvalid
	}
	if in.ResultAccess != nil {
		r := NormalizeResultAccess(*in.ResultAccess)
		// Only the plan's own actions can be selected outputs.
		for _, a := range r.ActionIDs {
			if !slices.ContainsFunc(in.Review.Actions, func(x GrantReviewAction) bool { return x.ActionID == a }) {
				return zero, false, value.ErrGrantInvalid
			}
		}
		g.ResultAccess = &r
		g.ResultAccessDigest = ResultAccessDigest(g.CaptureID, g.ExecutionDigest, r)
	}
	g.ReviewDigest = ReviewDigest(g, review)
	// Validate the prepared row with a provisional request time.
	probe := g
	probe.RequestedAt = s.Now()
	probe.ReviewUntil = probe.RequestedAt.Add(value.GrantReviewWindow)
	if !probe.Valid() {
		return zero, false, value.ErrGrantInvalid
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	eligible, err := s.collector(ctx, i, in.Target, value.CollectContext)
	if err != nil {
		return zero, false, err
	}
	if !eligible.Eligible {
		return zero, false, identity.ErrDenied
	}
	digest, err := json.Marshal(struct {
		ReviewDigest artifact.Digest
	}{g.ReviewDigest})
	if err != nil {
		return zero, false, ErrGrantUnavailable
	}
	out, replay, err := s.Store.RequestGrant(ctx, StoredGrantRequest{Grant: g, IdempotencyKey: in.IdempotencyKey, RequestDigest: sha256.Sum256(digest)}, recovery)
	if err != nil {
		return zero, false, err
	}
	if out.CaptureID != g.CaptureID || out.ReviewDigest != g.ReviewDigest || !sameRequester(out.Requester, i.Principal) {
		return zero, false, ErrGrantConflict
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	return out, replay, nil
}

func sameRequester(a, b identity.Principal) bool { return a == b }

// Covering checks, at use, that an approved grant covers starting exactly
// this capture plan for the calling identity: the stored row is intact
// (review digest recomputed), approved, unrevoked, unexpired, the caller is
// the requester and still has current collection eligibility. It returns
// value.ErrApprovalRequired (with the pending grant, if any) otherwise.
func (s GrantService) Covering(ctx context.Context, current identities.CurrentIdentity, captureID string, execution artifact.Digest, target value.Target) (value.Grant, time.Time, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() {
		return zero, time.Time{}, ErrGrantUnavailable
	}
	i, err := s.human(ctx, current, "evidence:capture")
	if err != nil {
		return zero, time.Time{}, err
	}
	g, err := s.Store.GrantByCapture(ctx, captureID)
	if errors.Is(err, ErrGrantNotFound) {
		return zero, time.Time{}, value.ErrApprovalRequired
	}
	if err != nil {
		return zero, time.Time{}, ErrGrantUnavailable
	}
	if g.Target != target || ReviewDigest(g, g.Review) != g.ReviewDigest {
		return g, time.Time{}, value.ErrGrantScope
	}
	if err = value.CheckCaptureUse(g, i, captureID, execution, g.ReviewDigest, s.Now()); err != nil {
		return g, time.Time{}, err
	}
	eligible, err := s.collector(ctx, i, target, value.CollectContext)
	if err != nil {
		return g, time.Time{}, err
	}
	if !eligible.Eligible {
		return g, time.Time{}, identity.ErrDenied
	}
	if err = s.final(ctx, current, i); err != nil {
		return g, time.Time{}, err
	}
	return g, identity.Earlier(identity.Earlier(eligible.ValidUntil, i.ValidUntil), g.ExpiresAt), nil
}

// Decide records one approve or deny decision of a distinct, currently
// eligible approver; approval also needs a current IdP step-up.
func (s GrantService) Decide(ctx context.Context, current identities.CurrentIdentity, grantID string, approve bool, reason, key string) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() {
		return zero, false, ErrGrantUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current)
	if err != nil {
		return zero, false, err
	}
	if !value.UUID(grantID) || !identity.Text(reason, 512) || !identity.Text(key, 128) {
		return zero, false, value.ErrGrantInvalid
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	g, err := s.Store.Grant(ctx, grantID)
	if err != nil {
		return zero, false, err
	}
	eligible, err := s.collector(ctx, i, g.Target, value.ApproveAction)
	if err != nil {
		return zero, false, err
	}
	// Who may decide is settled before any state of the grant is disclosed:
	// anyone else gets the same refusal as for an unknown grant.
	if sameHuman(g.Requester, i.Principal) {
		return zero, false, value.ErrSelfApproval
	}
	if !eligible.Eligible || eligible.Principal != i.Principal || !s.Now().Before(eligible.ValidUntil) {
		return zero, false, value.ErrNotApprover
	}
	if g.Decision != nil {
		// Only a retry of exactly this recorded decision (same reviewer and
		// key) is answered, as a replay; anything else is not pending.
		return s.Store.DecideGrant(ctx, GrantDecisionInput{GrantID: grantID, Approve: approve, Approver: i.Principal, Reason: reason, IdempotencyKey: key}, recovery)
	}
	if err = value.CheckDecision(g, i, eligible, approve, s.Now()); err != nil {
		return zero, false, err
	}
	in := GrantDecisionInput{GrantID: grantID, Approve: approve, Approver: i.Principal, Reason: reason, IdempotencyKey: key}
	if approve {
		in.ACR, in.AuthTime = i.Assurance.ACR, i.Assurance.AuthenticatedAt
	}
	out, replay, err := s.Store.DecideGrant(ctx, in, recovery)
	if err != nil {
		return zero, false, err
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	return out, replay, nil
}

// Revoke revokes a grant for its requester or a current approver.
// Revocation only restricts, so it needs no step-up.
func (s GrantService) Revoke(ctx context.Context, current identities.CurrentIdentity, grantID string, expected int64, key string) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() {
		return zero, false, ErrGrantUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current)
	if err != nil {
		return zero, false, err
	}
	if !value.UUID(grantID) || expected < 1 || expected > value.GrantMaxRevision || !identity.Text(key, 128) {
		return zero, false, value.ErrGrantInvalid
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	g, err := s.Store.Grant(ctx, grantID)
	if err != nil {
		return zero, false, err
	}
	approver := value.Result{}
	if !sameHuman(g.Requester, i.Principal) {
		if approver, err = s.collector(ctx, i, g.Target, value.ApproveAction); err != nil {
			return zero, false, err
		}
	}
	// Who may revoke is settled before any state of the grant is disclosed.
	currentApprover := approver.Eligible && approver.Principal == i.Principal && s.Now().Before(approver.ValidUntil)
	if !sameHuman(g.Requester, i.Principal) && !currentApprover {
		return zero, false, value.ErrNotApprover
	}
	if !g.RevokedAt.IsZero() {
		// Only the same revoker's retry with the same key is a replay.
		return s.Store.RevokeGrant(ctx, GrantRevocationInput{GrantID: grantID, Revoker: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}, recovery)
	}
	if !value.CanRevoke(g, i, approver, s.Now()) {
		return zero, false, value.ErrNotApprover
	}
	out, replay, err := s.Store.RevokeGrant(ctx, GrantRevocationInput{GrantID: grantID, Revoker: i.Principal, ExpectedRevision: expected, IdempotencyKey: key}, recovery)
	if err != nil {
		return zero, false, err
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	return out, replay, nil
}

func sameHuman(a, b identity.Principal) bool { return a.Issuer == b.Issuer && a.Subject == b.Subject }

// Get returns one grant to its requesting human or a current approver for
// its target; anyone else gets ErrGrantNotFound (no existence disclosure).
func (s GrantService) Get(ctx context.Context, current identities.CurrentIdentity, grantID string) (GrantView, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || !s.ready() {
		return GrantView{}, time.Time{}, ErrGrantUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current)
	if err != nil {
		return GrantView{}, time.Time{}, err
	}
	if !value.UUID(grantID) {
		return GrantView{}, time.Time{}, value.ErrGrantInvalid
	}
	g, err := s.Store.Grant(ctx, grantID)
	if errors.Is(err, ErrGrantNotFound) {
		return GrantView{}, time.Time{}, ErrGrantNotFound
	}
	if err != nil {
		return GrantView{}, time.Time{}, ErrGrantUnavailable
	}
	until := i.ValidUntil
	v := GrantView{Grant: g, Phase: g.Phase(s.Now()), CanResolve: i.Principal == g.Requester && slices.Contains(i.Scopes, "evidence:capture")}
	if !sameHuman(g.Requester, i.Principal) {
		r, err := s.collector(ctx, i, g.Target, value.ApproveAction)
		if err != nil || !r.Eligible {
			return GrantView{}, time.Time{}, ErrGrantNotFound
		}
		v.Approver, until = true, identity.Earlier(until, r.ValidUntil)
	}
	// Resume is a UI hint only. The original client must still have current
	// ordinary collection rights; this never transfers the grant to another
	// browser/MCP client or replaces the request's admission checks.
	var timing struct {
		Timing string `json:"timing"`
	}
	if i.Principal == g.Requester && slices.Contains(i.Scopes, "evidence:capture") &&
		json.Unmarshal(g.Scope, &timing) == nil && timing.Timing == "approvedAcceptance/v1" &&
		ReviewDigest(g, g.Review) == g.ReviewDigest &&
		value.CheckCaptureUse(g, i, g.CaptureID, g.ExecutionDigest, g.ReviewDigest, s.Now()) == nil {
		eligible, e := s.collector(ctx, i, g.Target, value.CollectContext)
		if e == nil && eligible.Eligible {
			v.CanResume = true
			until = identity.Earlier(until, eligible.ValidUntil)
			until = identity.Earlier(until, g.ExpiresAt)
		}
	}
	if json.Unmarshal(g.Review, &v.Review) != nil {
		return GrantView{}, time.Time{}, ErrGrantUnavailable
	}
	if err = s.final(ctx, current, i); err != nil {
		return GrantView{}, time.Time{}, err
	}
	return v, until, nil
}

// List returns the approver inbox (view "pending": reviewable requests of
// other people on targets where the caller is a current approver) or the
// caller's own requests (view "requested").
func (s GrantService) List(ctx context.Context, current identities.CurrentIdentity, view string, limit int) ([]GrantView, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || !s.ready() || limit < 1 || limit > 100 || view != "pending" && view != "requested" {
		return nil, time.Time{}, value.ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current)
	if err != nil {
		return nil, time.Time{}, err
	}
	var rows []value.Grant
	if view == "pending" {
		rows, err = s.Store.PendingGrants(ctx, 100)
	} else {
		rows, err = s.Store.RequestedGrants(ctx, i.Principal, 100)
	}
	if err != nil {
		return nil, time.Time{}, ErrGrantUnavailable
	}
	until := i.ValidUntil
	results := map[value.Target]value.Result{}
	out := make([]GrantView, 0, min(limit, len(rows)))
	for _, g := range rows {
		if len(out) == limit {
			break
		}
		v := GrantView{Grant: g, Phase: g.Phase(s.Now())}
		if view == "pending" {
			if sameHuman(g.Requester, i.Principal) || v.Phase != value.GrantPending {
				continue
			}
			r, ok := results[g.Target]
			if !ok {
				if r, err = s.collector(ctx, i, g.Target, value.ApproveAction); err != nil {
					r = value.Result{}
				}
				results[g.Target] = r
			}
			if !r.Eligible {
				continue
			}
			v.Approver, until = true, identity.Earlier(until, r.ValidUntil)
		} else if !sameHuman(g.Requester, i.Principal) {
			return nil, time.Time{}, ErrGrantUnavailable
		}
		if json.Unmarshal(g.Review, &v.Review) != nil {
			return nil, time.Time{}, ErrGrantUnavailable
		}
		out = append(out, v)
	}
	if err = s.final(ctx, current, i); err != nil {
		return nil, time.Time{}, err
	}
	return out, until, nil
}

// Materialize registers one verified committed output of the approved
// capture for one approved client (REQ-INV-002). Only C-03 creates
// children; an unknown or unpublished artifact never becomes a target, and
// a repeated delivery returns the existing child.
func (s GrantService) Materialize(ctx context.Context, parentID, clientID string, output value.VerifiedOutput) (value.GrantChild, bool, error) {
	var zero value.GrantChild
	if ctx == nil || ctx.Err() != nil || !s.ready() || !value.UUID(parentID) || !output.Valid() || !identity.Text(clientID, 256) {
		return zero, false, value.ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	g, err := s.Store.Grant(ctx, parentID)
	if err != nil {
		return zero, false, err
	}
	// The store decides "already registered" under the parent lock; checking
	// with registered=true here only rejects scope and phase early.
	if err = value.CheckMaterialize(g, output, clientID, true, s.Now()); err != nil {
		return zero, false, err
	}
	return s.Store.MaterializeGrantChild(ctx, GrantChildRequest{ChildID: s.NewID(), ParentID: parentID, ClientID: clientID, Output: output}, recovery)
}

// Use reserves one follow-up disclosure of a child grant for the calling
// identity before delivery: the requesting human through the child's
// client, current ordinary download eligibility for the target, a current
// parent and remaining shared pool. useID makes a retry idempotent.
func (s GrantService) Use(ctx context.Context, current identities.CurrentIdentity, childID, useID string, use value.GrantUse) (value.Grant, bool, error) {
	var zero value.Grant
	if ctx == nil || ctx.Err() != nil || !s.ready() || !value.UUID(childID) || !value.UUID(useID) {
		return zero, false, value.ErrGrantInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := s.human(ctx, current, "evidence:download")
	if err != nil {
		return zero, false, err
	}
	recovery, err := s.recovery(ctx)
	if err != nil {
		return zero, false, err
	}
	c, err := s.Store.GrantChild(ctx, childID)
	if err != nil {
		return zero, false, err
	}
	g, err := s.Store.Grant(ctx, c.ParentID)
	if err != nil {
		return zero, false, err
	}
	if use.Bytes < 0 || use.Operations < 0 || use.Bytes+use.Operations == 0 {
		return zero, false, value.ErrGrantInvalid
	}
	if err = value.CheckResultUse(g, c, i, use.Operation, s.Now()); err != nil {
		return zero, false, err
	}
	eligible, err := s.collector(ctx, i, g.Target, value.DownloadApproved)
	if err != nil {
		return zero, false, err
	}
	if !eligible.Eligible {
		return zero, false, identity.ErrDenied
	}
	out, replay, err := s.Store.ReserveGrantUse(ctx, GrantUseRequest{UseID: useID, ParentID: g.ID, ChildID: childID, Use: use}, recovery)
	if err != nil {
		return zero, false, err
	}
	if err = s.final(ctx, current, i); err != nil {
		return zero, false, err
	}
	return out, replay, nil
}
