package postgres

import (
	"bytes"
	"context"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

var _ app.PolicyGrantAttachmentStore = (*Policies)(nil)

func policyGrantAttachmentFromRow(r custodydb.PolicyGrantAttachment) (authorization.PolicyGrantAttachment, error) {
	a := authorization.PolicyGrantAttachment{ID: uid(r.ID), RootID: uid(r.RootID), InstallationID: uid(r.InstallationID),
		PolicyUID: r.PolicyUid, AcceptanceID: uid(r.AcceptanceID), GrantID: uid(r.GrantID), AuthoredGrantRef: r.AuthoredGrantRef,
		Actor: identity.Principal{Issuer: r.ActorIssuer, Subject: r.ActorSubject, ClientID: r.ActorClient, Kind: identity.Human}, AttachedAt: r.AttachedAt.Time}
	copy(a.AuthorityDigest[:], r.AuthorityDigest)
	if !a.Valid() || len(r.AuthorityDigest) != 32 || !bytes.Equal(r.ActorKey, policyGrantActorKey(a.Actor)) {
		return authorization.PolicyGrantAttachment{}, app.ErrGrantUnavailable
	}
	return a, nil
}

// AttachPolicyGrant is a semantic control receipt, not audit or reissuance.
// Public composition must call it only inside the existing activate_policy
// audited boundary, after that boundary acknowledges the encrypted intent.
func (s *Policies) AttachPolicyGrant(ctx context.Context, in app.PolicyGrantAttachmentInput) (authorization.PolicyGrantAttachment, bool, error) {
	var out authorization.PolicyGrantAttachment
	if s == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(in.ID) || !authorization.UUID(in.GrantID) ||
		!identity.Text(in.PolicyUID, 64) || !identity.Text(in.IdempotencyKey, 128) || !in.Actor.Principal.Valid() || in.Actor.Principal.Kind != identity.Human {
		return out, false, authorization.ErrGrantInvalid
	}
	digest := app.PolicyGrantAttachmentDigest(in)
	var replay bool
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, err := s.recovery.lock(ctx, q, s.root, in.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		receipt, err := q.ReadPolicyGrantAttachmentByKey(ctx, custodydb.ReadPolicyGrantAttachmentByKeyParams{RootID: id(s.root), ActorKey: policyGrantActorKey(in.Actor.Principal), IdempotencyKey: in.IdempotencyKey})
		replay = err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if replay {
			old, err := policyGrantAttachmentFromRow(receipt)
			if err != nil {
				return err
			}
			if old.Actor != in.Actor.Principal || old.PolicyUID != in.PolicyUID || old.GrantID != in.GrantID || !bytes.Equal(receipt.RequestDigest, digest[:]) {
				return app.ErrGrantConflict
			}
		}
		// The shared root makes source updates/settings clamps and attachment
		// serial. Exact prior replies are readable without reviving a pointer.
		var source custodydb.PolicySource
		if !replay {
			source, err = q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(s.root), PolicyUid: in.PolicyUID})
			if err != nil {
				return err
			}
		}
		row, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: id(s.root), ID: id(in.GrantID)})
		if err != nil {
			return err
		}
		grant, err := grantFromRow(row)
		if err != nil {
			return err
		}
		if grant.Kind != authorization.GrantPolicy || grant.Policy == nil || grant.Policy.Authority.PolicyUID != in.PolicyUID {
			return authorization.ErrGrantScope
		}
		authority := grant.Policy.Authority
		target := grant.Policy.Workload()
		p, err := permissionProjection(ctx, q, stream, authorization.Target{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID})
		if err != nil {
			return err
		}
		workload := authorization.WorkloadProjection{Target: target, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil,
			DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		manager := authorization.PolicyGrantManagementEligibility(in.Actor, workload, authority, now.Time)
		if !manager.Eligible {
			return identity.ErrDenied
		}
		until := manager.ValidUntil
		if !replay {
			snapshot, record, err := acceptedPolicyIn(ctx, q, s.root, s.installation, trust, source)
			if err != nil {
				return err
			}
			if err = authorization.CheckPolicyGrantAttachment(grant, snapshot.Authority, source.AuthoredGrantRef, now.Time); err != nil {
				return err
			}
			receipt, err = q.InsertPolicyGrantAttachment(ctx, custodydb.InsertPolicyGrantAttachmentParams{ID: id(in.ID), RootID: id(s.root), InstallationID: id(s.installation),
				PolicyUid: in.PolicyUID, AcceptanceID: id(record.ID), GrantID: id(in.GrantID), AuthorityDigest: authority.ScopeDigest[:], AuthoredGrantRef: source.AuthoredGrantRef,
				ActorIssuer: in.Actor.Principal.Issuer, ActorSubject: in.Actor.Principal.Subject, ActorClient: in.Actor.Principal.ClientID, IdempotencyKey: in.IdempotencyKey, RequestDigest: digest[:]})
			if err != nil {
				return err
			}
			changed, err := q.SetPolicyGrantAttachment(ctx, custodydb.SetPolicyGrantAttachmentParams{RootID: id(s.root), PolicyUid: in.PolicyUID, AcceptanceID: id(record.ID),
				AttachmentID: receipt.ID, AuthoredGrantRef: source.AuthoredGrantRef})
			if err != nil {
				return err
			}
			if changed != 1 {
				return authorization.ErrGrantScope
			}
			until = identity.Earlier(until, identity.Earlier(snapshot.FreshUntil, grant.PolicyNotAfter))
		}
		if out, err = policyGrantAttachmentFromRow(receipt); err != nil {
			return err
		}
		if out.RootID != s.root || out.InstallationID != s.installation || out.AcceptanceID != uid(row.PolicyAcceptanceID) || out.AuthorityDigest != authority.ScopeDigest {
			return authorization.ErrGrantScope
		}
		if err = s.recovery.check(ctx, q, trust, s.root, in.Recovery); err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Actor.Valid(now.Time) || !now.Time.Before(until) {
			return identity.ErrDenied
		}
		return ctx.Err()
	})
	if err != nil {
		if errors.Is(err, identity.ErrDenied) {
			return authorization.PolicyGrantAttachment{}, false, identity.ErrDenied
		}
		return authorization.PolicyGrantAttachment{}, false, grantError(err)
	}
	return out, replay, nil
}
