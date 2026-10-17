package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"time"

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
	var out authorization.AutomationProjection
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	if !a.Valid(now.Time) || a.InstallationID != installation || !target.Valid() || target.ClusterID != a.ClusterID || target.NamespaceUID != a.NamespaceUID || target.WorkloadUID != a.WorkloadUID {
		return out, cfg.ErrDenied
	}
	permissions, err := permissionProjection(ctx, q, s, target)
	if err != nil {
		return out, err
	}
	rows, err := q.SelectAutomationBasis(ctx, custodydb.SelectAutomationBasisParams{StreamID: s.ID, Uid: a.Delegation.UID, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, Column5: target.WorkloadUID})
	if err != nil {
		return out, err
	}
	if len(rows) != 1 {
		return out, cfg.ErrUnavailable
	}
	b := rows[0]
	if b.SeenSequence != s.Sequence || b.Generation != a.Delegation.Generation || !bytes.Equal(b.SpecDigest, a.Delegation.Digest[:]) || !b.AcknowledgedAt.Valid || len(b.AutomationJson) == 0 || len(b.AutomationJson) > 4096 {
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
		if delegation.BasisKey == b.BasisKey && delegation.Revision == a.Delegation && bytes.Equal(delegation.ScopeDigest[:], b.ScopeDigest) && sameAutomationEnvelope(delegation.Envelope, envelope) {
			matched = true
			break
		}
	}
	if !matched {
		return out, cfg.ErrUnavailable
	}
	out = authorization.AutomationProjection{InstallationID: installation, Delegation: a.Delegation, Envelope: envelope, ObservedAt: s.ObservedAt.Time, FreshUntil: permissions.FreshUntil, Permissions: permissions}
	if b.NotAfter.Valid {
		out.NotAfter = b.NotAfter.Time
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		return authorization.AutomationProjection{}, err
	}
	if !identity.Fresh(out.ObservedAt, out.FreshUntil, now.Time, 5*time.Second) || !a.Valid(now.Time) || (!out.NotAfter.IsZero() && !now.Time.Before(out.NotAfter)) {
		return authorization.AutomationProjection{}, cfg.ErrUnavailable
	}
	return out, nil
}

func sameAutomationEnvelope(a, b authorization.AutomationEnvelope) bool {
	return a.MaxLifetimeSeconds == b.MaxLifetimeSeconds && a.MaxExecutions == b.MaxExecutions && a.MaxBytes == b.MaxBytes && a.MaxObservedBytes == b.MaxObservedBytes && slices.Equal(a.AllowedActions, b.AllowedActions)
}
