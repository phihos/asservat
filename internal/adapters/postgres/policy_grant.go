package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func policyGrantKey(root string, actor identity.Principal, key string) custodydb.ReadPolicyGrantByKeyParams {
	return custodydb.ReadPolicyGrantByKeyParams{RootID: id(root), RequesterIssuer: actor.Issuer, RequesterSubject: actor.Subject,
		RequesterClient: actor.ClientID, RequesterKind: string(actor.Kind), IdempotencyKey: key}
}

// A hash is only an index key. Exact principal, policy, operation and original
// caller-input digest must match independently before returning a prior result.
func policyGrantRequestMatches(row custodydb.AccessGrant, actor identity.Principal, policy string, digest artifact.Digest) bool {
	return row.Kind == authorization.GrantPolicy && row.RequestOperation == "requestPolicyGrant" && row.RequesterIssuer == actor.Issuer &&
		row.RequesterSubject == actor.Subject && row.RequesterClient == actor.ClientID && row.RequesterKind == string(actor.Kind) &&
		row.PolicyUid.Valid && row.PolicyUid.String == policy && bytes.Equal(row.RequestDigest, digest[:])
}

func (s *AccessGrants) LookupPolicyGrantRequest(ctx context.Context, in app.PolicyGrantRequestLookup) (authorization.Grant, bool, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !in.Requester.Valid() || !identity.Text(in.PolicyUID, 64) || !identity.Text(in.IdempotencyKey, 128) || in.InputDigest == (artifact.Digest{}) {
		return authorization.Grant{}, false, authorization.ErrGrantInvalid
	}
	out, err := s.read(ctx, func(q *custodydb.Queries) (custodydb.AccessGrant, error) {
		row, err := q.ReadPolicyGrantByKey(ctx, policyGrantKey(s.root, in.Requester, in.IdempotencyKey))
		if err == nil && !policyGrantRequestMatches(row, in.Requester, in.PolicyUID, in.InputDigest) {
			return custodydb.AccessGrant{}, app.ErrGrantConflict
		}
		return row, err
	})
	if errors.Is(err, app.ErrGrantNotFound) {
		return authorization.Grant{}, false, nil
	}
	return out, err == nil, err
}

func (s *AccessGrants) requestPolicyGrant(ctx context.Context, in app.StoredGrantRequest, recovery artifact.RecoveryProof) (authorization.Grant, bool, error) {
	g := in.Grant
	if g.Policy == nil || !g.Requester.Valid() || !authorization.UUID(g.ID) || !g.RequestedAt.IsZero() || !g.PolicyNotAfter.IsZero() {
		return authorization.Grant{}, false, authorization.ErrGrantInvalid
	}
	scope, err := json.Marshal(g.Policy)
	if err != nil {
		return authorization.Grant{}, false, authorization.ErrGrantInvalid
	}
	reasons := make([]grantReasonWire, 0, len(g.Reasons))
	for _, r := range g.Reasons {
		reasons = append(reasons, grantReasonWire{r.ActionID, r.Code})
	}
	reasonBytes, err := json.Marshal(reasons)
	if err != nil {
		return authorization.Grant{}, false, authorization.ErrGrantInvalid
	}
	var out authorization.Grant
	var replay bool
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.recovery.lock(ctx, q, s.root, recovery)
		if err != nil {
			return err
		}
		// Serialize setting acceptance/clamps and source acceptance with issuance.
		if _, err = q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := q.ReadPolicyGrantByKey(ctx, policyGrantKey(s.root, g.Requester, in.IdempotencyKey))
		replay = err == nil
		if replay {
			if !policyGrantRequestMatches(row, g.Requester, g.Policy.Authority.PolicyUID, in.RequestDigest) {
				return app.ErrGrantConflict
			}
		} else if errors.Is(err, pgx.ErrNoRows) {
			source, err := q.SharePolicySource(ctx, custodydb.SharePolicySourceParams{RootID: id(s.root), PolicyUid: g.Policy.Authority.PolicyUID})
			if err != nil {
				return err
			}
			_, accepted, err := acceptedPolicyIn(ctx, q, s.root, s.recovery.installation, trust, source)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(accepted.Authority, g.Policy.Authority) {
				return authorization.ErrGrantScope
			}
			p := g.Policy
			row, err = q.InsertPolicyGrant(ctx, custodydb.InsertPolicyGrantParams{ID: id(g.ID), RootID: id(s.root), ClusterID: id(p.Authority.ClusterID),
				NamespaceUid: p.Authority.NamespaceUID, WorkloadUid: p.Authority.WorkloadUID, ExecutionDigest: g.ExecutionDigest[:], ReviewDigest: g.ReviewDigest[:],
				DataClass: g.DataClass, Reasons: reasonBytes, Review: g.Review, Scope: g.Scope, RequesterIssuer: g.Requester.Issuer,
				RequesterSubject: g.Requester.Subject, RequesterClient: g.Requester.ClientID, RequesterKind: string(g.Requester.Kind), LifetimeSeconds: int32(g.Lifetime / time.Second),
				IdempotencyKey: in.IdempotencyKey, RequestDigest: in.RequestDigest[:], PolicyUid: p.Authority.PolicyUID, PolicyAcceptanceID: id(accepted.ID),
				PolicyScope: scope, AuthorityNotAfter: ts(p.Authority.NotAfter), SettingsUid: p.ApprovalPolicyRef.UID, SettingsGeneration: p.ApprovalPolicyRef.Generation,
				SettingsDigest: p.ApprovalPolicyRef.Digest[:]})
			if err != nil {
				return err
			}
		} else {
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
		return authorization.Grant{}, false, grantError(err)
	}
	return out, replay, nil
}
