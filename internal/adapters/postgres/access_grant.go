package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccessGrants is the ADR-249 grant ledger (Migration 00097). It stores
// requests, one decision, one revocation, exact children and monotonic pool
// spend; it never decides who may approve. SQL re-checks self-approval,
// review window, decision, revocation, expiry and pool bounds.
type AccessGrants struct {
	ledger   *Ledger
	root     string
	recovery *RecoveryTransactionGuard
}

var _ authapp.GrantStore = (*AccessGrants)(nil)
var _ authapp.PolicyGrantRequestReader = (*AccessGrants)(nil)
var _ authapp.PolicyApprovalSettingsReader = (*AccessGrants)(nil)

func NewAccessGrants(ctx context.Context, pool *pgxpool.Pool, root string, recovery *RecoveryTransactionGuard) (*AccessGrants, error) {
	if !authorization.UUID(root) || recovery == nil || recovery.root != root {
		return nil, authorization.ErrGrantInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, authapp.ErrGrantUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(authapp.ErrGrantUnavailable, why)
	}
	return &AccessGrants{ledger: l, root: root, recovery: recovery}, nil
}

type grantReasonWire struct {
	ActionID string `json:"actionID"`
	Code     string `json:"code"`
}

type grantResultAccessWire struct {
	ActionIDs     []string `json:"actionIDs"`
	Operations    []string `json:"operations"`
	ClientIDs     []string `json:"clientIDs"`
	MaxArtifacts  int      `json:"maxArtifacts"`
	MaxBytes      int64    `json:"maxBytes"`
	MaxOperations int64    `json:"maxOperations"`
	NotAfter      string   `json:"notAfter"`
}

func optionalTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

func grantFromRow(r custodydb.AccessGrant) (authorization.Grant, error) {
	var reasons []grantReasonWire
	if json.Unmarshal(r.Reasons, &reasons) != nil || len(r.ExecutionDigest) != 32 || len(r.ReviewDigest) != 32 {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	g := authorization.Grant{ID: uid(r.ID), RootID: uid(r.RootID), Kind: r.Kind, PreviewID: uid(r.PreviewID), CaptureID: uid(r.CaptureID),
		Target:    authorization.Target{ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid.String},
		DataClass: r.DataClass, Scope: bytes.Clone(r.Scope), Review: bytes.Clone(r.Review),
		Requester:   identity.Principal{Issuer: r.RequesterIssuer, Subject: r.RequesterSubject, ClientID: r.RequesterClient, Kind: identity.Human},
		RequestedAt: r.RequestedAt.Time, ReviewUntil: r.ReviewUntil.Time, Lifetime: time.Duration(r.LifetimeSeconds) * time.Second,
		ExpiresAt: optionalTime(r.ExpiresAt), RevokedAt: optionalTime(r.RevokedAt), Revision: int64(r.Revision),
		Spent: authorization.GrantSpend{Artifacts: int(r.ArtifactsSpent), Bytes: r.BytesSpent, Operations: r.OperationsSpent}}
	copy(g.ExecutionDigest[:], r.ExecutionDigest)
	copy(g.ReviewDigest[:], r.ReviewDigest)
	if r.Kind == authorization.GrantPolicy {
		var scope authorization.PolicyGrantScope
		if strictJSON(string(r.PolicyScope), &scope) != nil || !r.PolicyUid.Valid || r.PolicyUid.String != scope.Authority.PolicyUID || !r.PolicyAcceptanceID.Valid ||
			r.PreviewID.Valid || r.CaptureID.Valid || r.PodUid.Valid ||
			g.Target.ClusterID != scope.Authority.ClusterID || g.Target.NamespaceUID != scope.Authority.NamespaceUID || g.Target.WorkloadUID != scope.Authority.WorkloadUID ||
			r.RequestOperation != "requestPolicyGrant" || !r.PolicyMaxExecutions.Valid || r.PolicyMaxExecutions.Int64 != scope.Limits.MaxExecutions ||
			!r.PolicyMaxBytes.Valid || r.PolicyMaxBytes.Int64 != scope.Limits.MaxBytes || !r.PolicyMaxObservedBytes.Valid || r.PolicyMaxObservedBytes.Int64 != scope.Limits.MaxObservedBytes {
			return authorization.Grant{}, authapp.ErrGrantUnavailable
		}
		g.Target = authorization.Target{}
		g.Policy, g.PolicyNotAfter = &scope, optionalTime(r.PolicyNotAfter)
		g.Requester.Kind = identity.Kind(r.RequesterKind)
		if !bytes.Equal(r.RequesterKey, policyGrantActorKey(g.Requester)) {
			return authorization.Grant{}, authapp.ErrGrantUnavailable
		}
		g.PolicySpend = authorization.PolicyGrantSpend{Executions: r.PolicyExecutionsSpent, CollectedBytes: r.PolicyBytesSpent, ObservedBytes: r.PolicyObservedBytesSpent}
	} else if r.Kind != authorization.GrantAdHocCapture || r.RequesterKind != string(identity.Human) || r.RequestOperation != "requestGrant" || len(r.RequesterKey) != 0 {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	for _, x := range reasons {
		g.Reasons = append(g.Reasons, authorization.SensitiveReason{ActionID: x.ActionID, Code: x.Code})
	}
	if len(r.ResultAccess) > 0 {
		var w grantResultAccessWire
		if json.Unmarshal(r.ResultAccess, &w) != nil {
			return authorization.Grant{}, authapp.ErrGrantUnavailable
		}
		notAfter, err := time.Parse(time.RFC3339Nano, w.NotAfter)
		if err != nil || len(r.ResultAccessDigest) != 32 || int64(w.MaxArtifacts) != int64(r.MaxArtifacts) || w.MaxBytes != r.MaxBytes || w.MaxOperations != r.MaxOperations || !r.NotAfter.Valid || !r.NotAfter.Time.Equal(notAfter) {
			return authorization.Grant{}, authapp.ErrGrantUnavailable
		}
		g.ResultAccess = &authorization.ResultAccess{ActionIDs: w.ActionIDs, Operations: w.Operations, ClientIDs: w.ClientIDs, MaxArtifacts: w.MaxArtifacts, MaxBytes: w.MaxBytes, MaxOperations: w.MaxOperations, NotAfter: r.NotAfter.Time}
		copy(g.ResultAccessDigest[:], r.ResultAccessDigest)
	}
	if r.Decision.Valid {
		g.Decision = &authorization.GrantDecision{Approved: r.Decision.String == "approved", Reason: r.DecisionReason.String, ACR: r.DecisionAcr.String, AuthenticatedAt: optionalTime(r.DecisionAuthTime), DecidedAt: r.DecidedAt.Time,
			Approver: identity.Principal{Issuer: r.ApproverIssuer.String, Subject: r.ApproverSubject.String, ClientID: r.ApproverClient.String, Kind: identity.Human}}
	}
	if r.RevokedAt.Valid {
		g.Revoker = identity.Principal{Issuer: r.RevokerIssuer.String, Subject: r.RevokerSubject.String, ClientID: r.RevokerClient.String, Kind: identity.Human}
	}
	var bindErr error
	g, bindErr = authapp.BindReviewedPolicyGrantStarts(g)
	if bindErr != nil {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	if !g.Valid() {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	return g, nil
}

func (s *AccessGrants) grant(r custodydb.AccessGrant) (authorization.Grant, error) {
	g, err := grantFromRow(r)
	if err != nil || g.RootID != s.root {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	return g, nil
}

func grantError(err error) error {
	for _, sentinel := range []error{authapp.ErrGrantConflict, authapp.ErrGrantNotFound, authorization.ErrGrantInvalid, authorization.ErrGrantNotPending, authorization.ErrSelfApproval,
		authorization.ErrGrantPoolExhausted, authorization.ErrGrantScope, authorization.ErrGrantRevoked, authorization.ErrGrantExpired, authorization.ErrGrantDenied} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return authapp.ErrGrantUnavailable
}

func (s *AccessGrants) RequestGrant(ctx context.Context, r authapp.StoredGrantRequest, recovery artifact.RecoveryProof) (authorization.Grant, bool, error) {
	var zero authorization.Grant
	g := r.Grant
	if s == nil || ctx == nil || ctx.Err() != nil || g.RootID != s.root || g.Decision != nil || !g.RevokedAt.IsZero() || !identity.Text(r.IdempotencyKey, 128) || r.RequestDigest == (artifact.Digest{}) {
		return zero, false, authorization.ErrGrantInvalid
	}
	if g.Kind == authorization.GrantPolicy {
		return s.requestPolicyGrant(ctx, r, recovery)
	}
	reasons := make([]grantReasonWire, 0, len(g.Reasons))
	for _, x := range g.Reasons {
		reasons = append(reasons, grantReasonWire{x.ActionID, x.Code})
	}
	reasonBytes, err := json.Marshal(reasons)
	if err != nil {
		return zero, false, authorization.ErrGrantInvalid
	}
	params := custodydb.InsertGrantParams{ID: id(g.ID), RootID: id(s.root), PreviewID: id(g.PreviewID), CaptureID: id(g.CaptureID), ClusterID: id(g.Target.ClusterID),
		NamespaceUid: g.Target.NamespaceUID, WorkloadUid: g.Target.WorkloadUID, PodUid: g.Target.PodUID, ExecutionDigest: g.ExecutionDigest[:], ReviewDigest: g.ReviewDigest[:],
		DataClass: g.DataClass, Reasons: reasonBytes, Review: g.Review, Scope: g.Scope, RequesterIssuer: g.Requester.Issuer, RequesterSubject: g.Requester.Subject, RequesterClient: g.Requester.ClientID,
		LifetimeSeconds: int32(g.Lifetime / time.Second), IdempotencyKey: r.IdempotencyKey, RequestDigest: r.RequestDigest[:]}
	if a := g.ResultAccess; a != nil {
		notAfter := a.NotAfter.UTC().Truncate(time.Microsecond)
		if !notAfter.Equal(a.NotAfter) {
			return zero, false, authorization.ErrGrantInvalid
		}
		if params.ResultAccess, err = json.Marshal(grantResultAccessWire{a.ActionIDs, a.Operations, a.ClientIDs, a.MaxArtifacts, a.MaxBytes, a.MaxOperations, notAfter.Format(time.RFC3339Nano)}); err != nil {
			return zero, false, authorization.ErrGrantInvalid
		}
		params.NotAfter = ts(notAfter)
		params.ResultAccessDigest = g.ResultAccessDigest[:]
		params.MaxArtifacts, params.MaxBytes, params.MaxOperations = int32(a.MaxArtifacts), a.MaxBytes, a.MaxOperations
	}
	var out authorization.Grant
	replay := false
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadGrantByKey(ctx, custodydb.ReadGrantByKeyParams{RootID: id(s.root), RequesterIssuer: g.Requester.Issuer, RequesterSubject: g.Requester.Subject, IdempotencyKey: r.IdempotencyKey})
		switch {
		case err == nil:
			if !bytes.Equal(row.RequestDigest, r.RequestDigest[:]) {
				return authapp.ErrGrantConflict
			}
			replay = true
		case errors.Is(err, pgx.ErrNoRows):
			// One request per capture identity: another key for the same plan
			// is a conflict, never a second review.
			if _, err = q.ReadGrantByCapture(ctx, custodydb.ReadGrantByCaptureParams{RootID: id(s.root), CaptureID: id(g.CaptureID)}); err == nil {
				return authapp.ErrGrantConflict
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if row, err = q.InsertGrant(ctx, params); err != nil {
				return err
			}
		default:
			return err
		}
		if out, err = s.grant(row); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, grantError(err)
	}
	return out, replay, nil
}

func (s *AccessGrants) read(ctx context.Context, f func(*custodydb.Queries) (custodydb.AccessGrant, error)) (authorization.Grant, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return authorization.Grant{}, authapp.ErrGrantUnavailable
	}
	var out authorization.Grant
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := f(q)
		if errors.Is(err, pgx.ErrNoRows) {
			return authapp.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		out, err = s.grant(row)
		return err
	})
	if err != nil {
		return authorization.Grant{}, grantError(err)
	}
	return out, nil
}

func (s *AccessGrants) Grant(ctx context.Context, grantID string) (authorization.Grant, error) {
	if !authorization.UUID(grantID) {
		return authorization.Grant{}, authorization.ErrGrantInvalid
	}
	return s.read(ctx, func(q *custodydb.Queries) (custodydb.AccessGrant, error) {
		return q.ReadGrant(ctx, custodydb.ReadGrantParams{RootID: id(s.root), ID: id(grantID)})
	})
}

func (s *AccessGrants) GrantByCapture(ctx context.Context, captureID string) (authorization.Grant, error) {
	if !authorization.UUID(captureID) {
		return authorization.Grant{}, authorization.ErrGrantInvalid
	}
	return s.read(ctx, func(q *custodydb.Queries) (custodydb.AccessGrant, error) {
		return q.ReadGrantByCapture(ctx, custodydb.ReadGrantByCaptureParams{RootID: id(s.root), CaptureID: id(captureID)})
	})
}

func (s *AccessGrants) list(ctx context.Context, f func(*custodydb.Queries) ([]custodydb.AccessGrant, error)) ([]authorization.Grant, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, authapp.ErrGrantUnavailable
	}
	var out []authorization.Grant
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := f(q)
		if err != nil {
			return err
		}
		out = make([]authorization.Grant, 0, len(rows))
		for _, row := range rows {
			g, err := s.grant(row)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return nil
	})
	if err != nil {
		return nil, grantError(err)
	}
	return out, nil
}

func (s *AccessGrants) PendingGrants(ctx context.Context, limit int) ([]authorization.Grant, error) {
	if limit < 1 || limit > 100 {
		return nil, authorization.ErrGrantInvalid
	}
	return s.list(ctx, func(q *custodydb.Queries) ([]custodydb.AccessGrant, error) {
		return q.ListPendingGrants(ctx, custodydb.ListPendingGrantsParams{RootID: id(s.root), RowLimit: int32(limit)})
	})
}

func (s *AccessGrants) RequestedGrants(ctx context.Context, requester identity.Principal, limit int) ([]authorization.Grant, error) {
	if limit < 1 || limit > 100 || !requester.Valid() {
		return nil, authorization.ErrGrantInvalid
	}
	return s.list(ctx, func(q *custodydb.Queries) ([]custodydb.AccessGrant, error) {
		return q.ListRequestedGrants(ctx, custodydb.ListRequestedGrantsParams{RootID: id(s.root), RequesterIssuer: requester.Issuer, RequesterSubject: requester.Subject, RequesterKind: string(requester.Kind), RequesterClient: requester.ClientID, RowLimit: int32(limit)})
	})
}

func grantText(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

// DecideGrant records one decision. A retry by the same reviewer with the
// same key and decision returns the recorded row as a replay; any other
// update of a decided, revoked or lapsed request is ErrGrantNotPending, and
// the database refuses self-approval even if a caller skipped the service.
func (s *AccessGrants) DecideGrant(ctx context.Context, in authapp.GrantDecisionInput, recovery artifact.RecoveryProof) (authorization.Grant, bool, error) {
	var zero authorization.Grant
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(in.GrantID) || !in.Approver.Valid() || in.Approver.Kind != identity.Human || !identity.Text(in.Reason, 512) || !identity.Text(in.IdempotencyKey, 128) {
		return zero, false, authorization.ErrGrantInvalid
	}
	// Carry the caller's original effect deadline through the database clock;
	// row-lock waits cannot turn a stale reviewer/step-up into a decision.
	until := recovery.FreshUntil
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	until = until.UTC().Truncate(time.Microsecond)
	decision := "denied"
	params := custodydb.DecideGrantParams{EffectUntil: ts(until), RootID: id(s.root), ID: id(in.GrantID), ApproverIssuer: in.Approver.Issuer, ApproverSubject: in.Approver.Subject, ApproverClient: in.Approver.ClientID, DecisionReason: in.Reason, DecisionKey: in.IdempotencyKey}
	stepped := identity.Text(in.ACR, 128) && !in.AuthTime.IsZero()
	if in.Approve {
		decision = "approved"
		if stepped {
			params.DecisionAcr, params.DecisionAuthTime = grantText(in.ACR), ts(in.AuthTime)
		}
	}
	params.Decision = decision
	var out authorization.Grant
	replay := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		current, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: id(s.root), ID: id(in.GrantID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return authapp.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		if current.Decision.Valid {
			if current.DecisionKey.String != in.IdempotencyKey || current.Decision.String != decision || current.ApproverIssuer.String != in.Approver.Issuer || current.ApproverSubject.String != in.Approver.Subject {
				return authorization.ErrGrantNotPending
			}
			replay = true
		} else {
			if current.RequesterIssuer == in.Approver.Issuer && current.RequesterSubject == in.Approver.Subject {
				return authorization.ErrSelfApproval
			}
			// An approval records the verified authentication context.
			if in.Approve && !stepped {
				return authorization.ErrStepUpRequired
			}
			if current, err = q.DecideGrant(ctx, params); errors.Is(err, pgx.ErrNoRows) {
				// Revoked or no longer reviewable.
				return authorization.ErrGrantNotPending
			} else if err != nil {
				return err
			}
		}
		if out, err = s.grant(current); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, grantError(err)
	}
	return out, replay, nil
}

// RevokeGrant revokes once at the expected revision. A retry by the same
// revoker and key is a replay; another revision is ErrGrantConflict.
func (s *AccessGrants) RevokeGrant(ctx context.Context, in authapp.GrantRevocationInput, recovery artifact.RecoveryProof) (authorization.Grant, bool, error) {
	var zero authorization.Grant
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(in.GrantID) || !in.Revoker.Valid() || in.ExpectedRevision < 1 || in.ExpectedRevision > authorization.GrantMaxRevision || !identity.Text(in.IdempotencyKey, 128) {
		return zero, false, authorization.ErrGrantInvalid
	}
	var out authorization.Grant
	replay := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		current, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: id(s.root), ID: id(in.GrantID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return authapp.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case current.RevokedAt.Valid:
			if current.RevokeKey.String != in.IdempotencyKey || current.RevokerIssuer.String != in.Revoker.Issuer || current.RevokerSubject.String != in.Revoker.Subject {
				return authorization.ErrGrantRevoked
			}
			replay = true
		case int64(current.Revision) != in.ExpectedRevision:
			return authapp.ErrGrantConflict
		default:
			if current, err = q.RevokeGrant(ctx, custodydb.RevokeGrantParams{RootID: id(s.root), ID: id(in.GrantID), RevokerIssuer: in.Revoker.Issuer, RevokerSubject: in.Revoker.Subject, RevokerClient: in.Revoker.ClientID, RevokeKey: in.IdempotencyKey, ExpectedRevision: int16(in.ExpectedRevision)}); err != nil {
				return err
			}
		}
		if out, err = s.grant(current); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, grantError(err)
	}
	return out, replay, nil
}

func childFromRow(r custodydb.AccessGrantChild, parent authorization.Grant) (authorization.GrantChild, error) {
	c := authorization.GrantChild{ID: uid(r.ID), ParentID: uid(r.ParentID), ClientID: r.ClientID, CreatedAt: r.CreatedAt.Time,
		Output: authorization.VerifiedOutput{CaptureID: uid(r.CaptureID), ActionID: r.ActionID, ArtifactID: uid(r.ArtifactID), ExecutionDigest: parent.ExecutionDigest, Target: parent.Target}}
	if len(r.ArtifactDigest) != 32 {
		return authorization.GrantChild{}, authapp.ErrGrantUnavailable
	}
	copy(c.Output.ArtifactDigest[:], r.ArtifactDigest)
	if !c.Valid() || c.ParentID != parent.ID || c.Output.CaptureID != parent.CaptureID {
		return authorization.GrantChild{}, authapp.ErrGrantUnavailable
	}
	return c, nil
}

// MaterializeGrantChild registers one verified output for one approved
// client in one transaction: parent row lock, current decision, revocation,
// expiry and scope, the published locator of exactly this capture and
// target, the distinct-artifact count and the idempotent child insert.
func (s *AccessGrants) MaterializeGrantChild(ctx context.Context, in authapp.GrantChildRequest, recovery artifact.RecoveryProof) (authorization.GrantChild, bool, error) {
	var zero authorization.GrantChild
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(in.ChildID) || !authorization.UUID(in.ParentID) || !in.Output.Valid() || !identity.Text(in.ClientID, 256) {
		return zero, false, authorization.ErrGrantInvalid
	}
	var out authorization.GrantChild
	replay := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		row, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: id(s.root), ID: id(in.ParentID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return authapp.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		parent, err := s.grant(row)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		existing, err := q.ReadGrantChild(ctx, custodydb.ReadGrantChildParams{ParentID: id(in.ParentID), ArtifactID: id(in.Output.ArtifactID), ClientID: in.ClientID})
		if err == nil {
			// A repeated commit delivery: the same child, still only while
			// the parent is current.
			if err = authorization.CheckMaterialize(parent, in.Output, in.ClientID, true, now.Time); err != nil {
				return err
			}
			if !bytes.Equal(existing.ArtifactDigest, in.Output.ArtifactDigest[:]) || existing.ActionID != in.Output.ActionID {
				return authorization.ErrGrantScope
			}
			replay = true
			out, err = childFromRow(existing, parent)
			if err != nil {
				return err
			}
			return s.recovery.check(ctx, q, trust, s.root, recovery)
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		registered, err := q.GrantArtifactRegistered(ctx, custodydb.GrantArtifactRegisteredParams{ParentID: id(in.ParentID), ArtifactID: id(in.Output.ArtifactID)})
		if err != nil {
			return err
		}
		if err = authorization.CheckMaterialize(parent, in.Output, in.ClientID, registered, now.Time); err != nil {
			return err
		}
		t := parent.Target
		if _, err = q.ReadGrantOutputLocator(ctx, custodydb.ReadGrantOutputLocatorParams{RootID: id(s.root), ArtifactID: id(in.Output.ArtifactID), CaptureID: id(parent.CaptureID),
			ClusterID: id(t.ClusterID), NamespaceUid: t.NamespaceUID, WorkloadUid: t.WorkloadUID, PodUid: t.PodUID}); errors.Is(err, pgx.ErrNoRows) {
			// No published artifact of this capture: never an executable target.
			return authorization.ErrGrantScope
		} else if err != nil {
			return err
		}
		if !registered {
			if _, err = q.ChargeGrantArtifact(ctx, custodydb.ChargeGrantArtifactParams{RootID: id(s.root), ID: id(in.ParentID)}); errors.Is(err, pgx.ErrNoRows) {
				return authorization.ErrGrantPoolExhausted
			} else if err != nil {
				return err
			}
		}
		child, err := q.InsertGrantChild(ctx, custodydb.InsertGrantChildParams{ID: id(in.ChildID), RootID: id(s.root), ParentID: id(in.ParentID), CaptureID: id(parent.CaptureID),
			ActionID: in.Output.ActionID, ArtifactID: id(in.Output.ArtifactID), ArtifactDigest: in.Output.ArtifactDigest[:], ClientID: in.ClientID})
		if err != nil {
			return err
		}
		if out, err = childFromRow(child, parent); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, grantError(err)
	}
	return out, replay, nil
}

func (s *AccessGrants) GrantChild(ctx context.Context, childID string) (authorization.GrantChild, error) {
	var zero authorization.GrantChild
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(childID) {
		return zero, authorization.ErrGrantInvalid
	}
	var out authorization.GrantChild
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadGrantChildByID(ctx, custodydb.ReadGrantChildByIDParams{RootID: id(s.root), ID: id(childID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return authapp.ErrGrantNotFound
		}
		if err != nil {
			return err
		}
		prow, err := q.ReadGrant(ctx, custodydb.ReadGrantParams{RootID: id(s.root), ID: row.ParentID})
		if err != nil {
			return err
		}
		parent, err := s.grant(prow)
		if err != nil {
			return err
		}
		out, err = childFromRow(row, parent)
		return err
	})
	if err != nil {
		return zero, grantError(err)
	}
	return out, nil
}

// ReserveGrantUse charges one use to the parent's shared pool before
// delivery, in one transaction with its operation record. The UPDATE holds
// the parent row lock, so a concurrent revocation or another reservation is
// serialized: after a revocation commits no reservation can succeed, and the
// pool is never exceeded. A retry with the same use ID charges nothing.
func (s *AccessGrants) ReserveGrantUse(ctx context.Context, in authapp.GrantUseRequest, recovery artifact.RecoveryProof) (authorization.Grant, bool, error) {
	var zero authorization.Grant
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(in.UseID) || !authorization.UUID(in.ParentID) || !authorization.UUID(in.ChildID) || in.Use.Operation != authorization.GrantDownloadOperation || in.Use.Bytes < 0 || in.Use.Operations < 0 || in.Use.Bytes+in.Use.Operations == 0 {
		return zero, false, authorization.ErrGrantInvalid
	}
	var out authorization.Grant
	replay := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		replay = false
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		var row custodydb.AccessGrant
		previous, err := q.ReadGrantUse(ctx, custodydb.ReadGrantUseParams{RootID: id(s.root), ID: id(in.UseID)})
		switch {
		case err == nil:
			if uid(previous.ParentID) != in.ParentID || uid(previous.ChildID) != in.ChildID || previous.Bytes != in.Use.Bytes || previous.Operations != in.Use.Operations {
				return authapp.ErrGrantConflict
			}
			// The original reservation stands; its delivery is rechecked by
			// the caller against the current parent.
			if row, err = q.ReadGrant(ctx, custodydb.ReadGrantParams{RootID: id(s.root), ID: id(in.ParentID)}); err != nil {
				return err
			}
			replay = true
		case errors.Is(err, pgx.ErrNoRows):
			child, err := q.ReadGrantChildByID(ctx, custodydb.ReadGrantChildByIDParams{RootID: id(s.root), ID: id(in.ChildID)})
			if errors.Is(err, pgx.ErrNoRows) || err == nil && uid(child.ParentID) != in.ParentID {
				return authorization.ErrGrantScope
			} else if err != nil {
				return err
			}
			row, err = q.ChargeGrantUse(ctx, custodydb.ChargeGrantUseParams{RootID: id(s.root), ID: id(in.ParentID), Bytes: in.Use.Bytes, Operations: in.Use.Operations})
			if errors.Is(err, pgx.ErrNoRows) {
				// Distinguish a final phase from an exhausted pool.
				current, err := q.ReadGrant(ctx, custodydb.ReadGrantParams{RootID: id(s.root), ID: id(in.ParentID)})
				if err != nil {
					return err
				}
				g, err := s.grant(current)
				if err != nil {
					return err
				}
				now, err := q.CurrentTime(ctx)
				if err != nil {
					return err
				}
				switch g.Phase(now.Time) {
				case authorization.GrantRevoked:
					return authorization.ErrGrantRevoked
				case authorization.GrantExpired:
					return authorization.ErrGrantExpired
				case authorization.GrantApproved:
					return authorization.ErrGrantPoolExhausted
				}
				return authorization.ErrGrantDenied
			} else if err != nil {
				return err
			}
			if _, err = q.InsertGrantUse(ctx, custodydb.InsertGrantUseParams{ID: id(in.UseID), RootID: id(s.root), ParentID: id(in.ParentID), ChildID: id(in.ChildID), Operation: in.Use.Operation, Bytes: in.Use.Bytes, Operations: in.Use.Operations}); err != nil {
				return err
			}
		default:
			return err
		}
		if out, err = s.grant(row); err != nil {
			return err
		}
		if err = s.recovery.check(ctx, q, trust, s.root, recovery); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, false, grantError(err)
	}
	return out, replay, nil
}
