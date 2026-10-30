package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AutomationAuthorities is a read-only eligibility facet. The installation/root
// association comes from private composition, not an authored policy field.
// Final effect transactions still need recovery, privacy, grant and quota fences.
type AutomationAuthorities struct {
	permissions  *Permissions
	installation string
}

var _ app.AutomationAuthorityReader = (*AutomationAuthorities)(nil)

func NewAutomationAuthorities(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*AutomationAuthorities, error) {
	if !authorization.UUID(installation) {
		return nil, cfg.ErrInvalid
	}
	p, err := NewPermissions(ctx, pool, root)
	if err != nil {
		return nil, err
	}
	return &AutomationAuthorities{permissions: p, installation: installation}, nil
}

func (r *AutomationAuthorities) PolicyAutomationAuthority(ctx context.Context, a authorization.AcceptedPolicyAuthority, target authorization.Target) (authorization.AutomationProjection, error) {
	var out authorization.AutomationProjection
	err := r.permissions.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.SharePermissionStream(ctx, id(r.permissions.root))
		if err != nil {
			return err
		}
		out, err = automationProjection(ctx, q, s, r.installation, a, target)
		return err
	})
	if err != nil {
		return authorization.AutomationProjection{}, err
	}
	return out, nil
}

// Caller holds the permission stream lock for the entire transaction. Audited
// ordinary assignments alone do not prove an automation envelope was accepted:
// its own current source snapshot must match the acknowledged immutable record.
func automationProjection(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, installation string, a authorization.AcceptedPolicyAuthority, target authorization.Target) (authorization.AutomationProjection, error) {
	return automationProjectionFor(ctx, q, s, installation, a.Delegation, target, &a)
}

// Shared fixed-purpose read. A nil authority is permitted only through the
// typed workload activation port and excludes every per-Pod review.
func automationProjectionFor(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, installation string, basis identity.Revision, target authorization.Target, authority *authorization.AcceptedPolicyAuthority) (authorization.AutomationProjection, error) {
	return automationProjectionForWithPermissions(ctx, q, s, installation, basis, target, authority, nil)
}

func automationProjectionForWithPermissions(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, installation string, basis identity.Revision, target authorization.Target, authority *authorization.AcceptedPolicyAuthority, lockedPermissions *authorization.Projection) (authorization.AutomationProjection, error) {
	var out authorization.AutomationProjection
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	workload := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
	if !workload.Valid() || !basis.Valid() || authority == nil && target.PodUID != "" || authority != nil && (!authority.Valid(now.Time) || authority.InstallationID != installation || !target.Valid() || target.ClusterID != authority.ClusterID || target.NamespaceUID != authority.NamespaceUID || target.WorkloadUID != authority.WorkloadUID) {
		return out, cfg.ErrDenied
	}
	var permissions authorization.Projection
	if lockedPermissions != nil {
		if lockedPermissions.Target != target {
			return out, cfg.ErrChanged
		}
		permissions = *lockedPermissions
	} else {
		permissions, err = permissionProjection(ctx, q, s, target)
		if err != nil {
			return out, err
		}
	}
	rows, err := q.SelectAutomationBasis(ctx, custodydb.SelectAutomationBasisParams{StreamID: s.ID, Uid: basis.UID, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, Column5: target.WorkloadUID})
	if err != nil {
		return out, err
	}
	if len(rows) != 1 {
		return out, cfg.ErrUnavailable
	}
	b := rows[0]
	if b.SeenSequence != s.Sequence || b.Generation != basis.Generation || !bytes.Equal(b.SpecDigest, basis.Digest[:]) || !b.AcknowledgedAt.Valid || len(b.AutomationJson) == 0 || len(b.AutomationJson) > 4096 {
		return out, cfg.ErrUnavailable
	}
	var envelope authorization.AutomationEnvelope
	decoder := json.NewDecoder(bytes.NewReader(b.AutomationJson))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || !envelope.Valid() {
		return out, cfg.ErrUnavailable
	}
	audited, err := q.ReadAuthorityAudit(ctx, b.AutomationAuditID)
	if err != nil {
		return out, err
	}
	record, err := decodeAuthority(audited)
	if err != nil {
		return out, err
	}
	if !currentAuthorityAudit(audited, s.ID, b.AutomationAuditID) || record.RootID != uid(s.ID) || record.Epoch != uid(s.Epoch) || record.Sequence != s.Sequence {
		return out, cfg.ErrUnavailable
	}
	matched := false
	for _, delegation := range record.Automation {
		if delegation.BasisKey == b.BasisKey && delegation.Revision == basis && bytes.Equal(delegation.ScopeDigest[:], b.ScopeDigest) && sameAutomationEnvelope(delegation.Envelope, envelope) {
			matched = true
			break
		}
	}
	if !matched {
		return out, cfg.ErrUnavailable
	}
	out = authorization.AutomationProjection{InstallationID: installation, Delegation: basis, Envelope: envelope, ObservedAt: s.ObservedAt.Time, FreshUntil: permissions.FreshUntil, Permissions: permissions}
	if b.NotAfter.Valid {
		out.NotAfter = b.NotAfter.Time
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		return authorization.AutomationProjection{}, err
	}
	if !identity.Fresh(out.ObservedAt, out.FreshUntil, now.Time, authorization.PermissionObservationInterval) || authority != nil && !authority.Valid(now.Time) || (!out.NotAfter.IsZero() && !now.Time.Before(out.NotAfter)) {
		return authorization.AutomationProjection{}, cfg.ErrUnavailable
	}
	return out, nil
}

func sameAutomationEnvelope(a, b authorization.AutomationEnvelope) bool {
	return a.MaxLifetimeSeconds == b.MaxLifetimeSeconds && a.MaxExecutions == b.MaxExecutions && a.MaxBytes == b.MaxBytes && a.MaxObservedBytes == b.MaxObservedBytes && slices.Equal(a.AllowedActions, b.AllowedActions)
}

func (r *AutomationAuthorities) PolicyWorkloadAutomation(ctx context.Context, target authorization.WorkloadTarget, basis identity.Revision) (authorization.WorkloadAutomationProjection, error) {
	if r == nil || !target.Valid() || !basis.Valid() {
		return authorization.WorkloadAutomationProjection{}, cfg.ErrInvalid
	}
	var projection authorization.AutomationProjection
	err := r.permissions.transaction(ctx, func(q *custodydb.Queries) error {
		stream, err := q.SharePermissionStream(ctx, id(r.permissions.root))
		if err != nil {
			return err
		}
		projection, err = automationProjectionFor(ctx, q, stream, r.installation, basis, authorization.Target{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}, nil)
		return err
	})
	if err != nil {
		return authorization.WorkloadAutomationProjection{}, err
	}
	p := projection.Permissions
	permissions := authorization.WorkloadProjection{Target: target, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}
	return authorization.WorkloadAutomationProjection{InstallationID: projection.InstallationID, Delegation: projection.Delegation, Envelope: projection.Envelope, ObservedAt: projection.ObservedAt, FreshUntil: projection.FreshUntil, NotAfter: projection.NotAfter, Disabled: projection.Disabled, Permissions: permissions}, nil
}
