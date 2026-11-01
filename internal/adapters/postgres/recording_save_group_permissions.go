package postgres

import (
	"bytes"
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// Created only after this transaction's permission-stream FOR UPDATE lock and
// replay lookup. Supported permission/receipt writers take that root lock;
// decision-time reviews take its conflicting SHARE lock. Only raw projections
// and one shared policy/delegation facts bundle are retained, never decisions
// or mutable budgets. Every caller still evaluates expiry against current DB time.
// Nothing survives the transaction; full audit/accepted-record bodies are discarded.
type recordingGroupFacts struct {
	q        *custodydb.Queries
	stream   custodydb.PermissionStream
	byTarget map[authorization.Target]authorization.Projection
	policy   *recordingGroupPolicyFacts
	basis    *recordingGroupBasisFacts
}

func newRecordingGroupFacts(q *custodydb.Queries, stream custodydb.PermissionStream) *recordingGroupFacts {
	stream.ProjectionDigest = slices.Clone(stream.ProjectionDigest)
	stream.TrustDigest = slices.Clone(stream.TrustDigest)
	return &recordingGroupFacts{q: q, stream: stream, byTarget: make(map[authorization.Target]authorization.Projection)}
}

func (p *recordingGroupFacts) read(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, target authorization.Target) (authorization.Projection, error) {
	if p == nil {
		return permissionProjection(ctx, q, stream, target)
	}
	if ctx.Err() != nil {
		return authorization.Projection{}, ctx.Err()
	}
	if !p.owns(q, stream) || !target.Valid() {
		return authorization.Projection{}, value.ErrInvalid
	}
	if projection, ok := p.byTarget[target]; ok {
		return projection, nil
	}
	if len(p.byTarget) >= value.MaxRecordingSaveGroupChildren {
		return authorization.Projection{}, value.ErrCapacity
	}
	projection, err := permissionProjection(ctx, q, stream, target)
	if err != nil {
		return authorization.Projection{}, err
	}
	if projection.Target != target {
		return authorization.Projection{}, value.ErrChanged
	}
	p.byTarget[target] = projection
	return projection, nil
}

// A group's exact policy/workload is fixed by its protected full selection.
type recordingGroupPolicyFacts struct {
	root, installation, policy string
	source                     value.PolicySource
	snapshot                   authorization.AcceptedPolicySnapshot
	trust                      custodydb.FleetCurrentTrust
	observedAt                 time.Time
}
type recordingGroupBasisFacts struct {
	installation, policy string
	scope                artifact.Digest
	delegation           identity.Revision
	target               authorization.WorkloadTarget
	facts                automationBasisFacts
	observedAt           time.Time
}

func (p *recordingGroupFacts) owns(q *custodydb.Queries, s custodydb.PermissionStream) bool {
	return p != nil && q == p.q && s.ID == p.stream.ID && s.Epoch == p.stream.Epoch && s.Sequence == p.stream.Sequence && s.InitialAuditID == p.stream.InitialAuditID && s.ObservedAt == p.stream.ObservedAt && s.FreshUntil == p.stream.FreshUntil && s.LeaseUntil == p.stream.LeaseUntil && s.Suspended == p.stream.Suspended && bytes.Equal(s.ProjectionDigest, p.stream.ProjectionDigest) && bytes.Equal(s.TrustDigest, p.stream.TrustDigest)
}
func groupPolicyTarget(a authorization.AcceptedPolicyAuthority, t authorization.Target) bool {
	return t.Valid() && t.ClusterID == a.ClusterID && t.NamespaceUID == a.NamespaceUID && t.WorkloadUID == a.WorkloadUID
}
func (p *recordingGroupFacts) acceptedPolicy(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, trust custodydb.FleetCurrentTrust, root, installation, policy string, target authorization.Target, observedAt time.Time) (authorization.AcceptedPolicySnapshot, error) {
	var zero authorization.AcceptedPolicySnapshot
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	if !p.owns(q, stream) || uid(stream.ID) != root || uid(trust.InstallationID) != installation {
		return zero, value.ErrInvalid
	}
	if p.policy == nil {
		row, err := q.ReadPolicySourceRow(ctx, custodydb.ReadPolicySourceRowParams{RootID: id(root), PolicyUid: policy})
		if err != nil {
			return zero, err
		}
		snapshot, _, err := acceptedPolicyIn(ctx, q, root, installation, trust, row)
		if err != nil {
			return zero, err
		}
		if !groupPolicyTarget(snapshot.Authority, target) {
			return zero, value.ErrDenied
		}
		trust.SourceDigest = slices.Clone(trust.SourceDigest)
		p.policy = &recordingGroupPolicyFacts{root: root, installation: installation, policy: policy, source: policySource(row), snapshot: snapshot, trust: trust, observedAt: observedAt}
		return snapshot, nil
	}
	f := p.policy
	if f.root != root || f.installation != installation || f.policy != policy || !groupPolicyTarget(f.snapshot.Authority, target) || !sameGroupTrust(f.trust, trust) {
		return zero, value.ErrChanged
	}
	// Retain the original two database clock checks around immutable policy facts.
	first, err := q.CurrentTime(ctx)
	if err != nil {
		return zero, err
	}
	if first.Time.Before(f.observedAt) || observedAt.Before(f.observedAt) || f.source.InstallationID != installation || f.source.Deleted || f.source.Suspended || !f.source.Valid(first.Time) {
		return zero, value.ErrUnavailable
	}
	last, err := q.CurrentTime(ctx)
	if err != nil {
		return zero, err
	}
	recovery, err := recoveryState(trust, last.Time, last.Time)
	if err != nil {
		return zero, err
	}
	until := identity.Earlier(f.snapshot.FreshUntil, identity.Earlier(recovery.FreshUntil, f.snapshot.Authority.NotAfter))
	if last.Time.Before(first.Time) || !f.source.Valid(last.Time) || !f.snapshot.Authority.Valid(last.Time) || !last.Time.Before(until) {
		return zero, value.ErrUnavailable
	}
	return f.snapshot, nil
}
func (p *recordingGroupFacts) automationBasis(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, installation string, a authorization.AcceptedPolicyAuthority, target authorization.Target, observedAt time.Time) (automationBasisFacts, error) {
	var zero automationBasisFacts
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	if !p.owns(q, stream) || installation != a.InstallationID || !groupPolicyTarget(a, target) {
		return zero, value.ErrInvalid
	}
	workload := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
	if p.basis == nil {
		data, err := readAutomationBasis(ctx, q, stream, a.Delegation, target)
		if err != nil {
			return zero, err
		}
		p.basis = &recordingGroupBasisFacts{installation: installation, policy: a.PolicyUID, scope: a.ScopeDigest, delegation: a.Delegation, target: workload, facts: data, observedAt: observedAt}
	}
	f := p.basis
	if observedAt.Before(f.observedAt) || f.installation != installation || f.policy != a.PolicyUID || f.scope != a.ScopeDigest || f.delegation != a.Delegation || f.target != workload {
		return zero, value.ErrChanged
	}
	return f.facts, nil
}
func (p *recordingGroupFacts) automation(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, installation string, a authorization.AcceptedPolicyAuthority, target authorization.Target, projection authorization.Projection) (authorization.AutomationProjection, error) {
	return automationProjectionForWithFacts(ctx, q, stream, installation, a.Delegation, target, &a, &projection, p)
}

func sameGroupTrust(a, b custodydb.FleetCurrentTrust) bool {
	return a.InstallationID == b.InstallationID && a.IssuerEpoch == b.IssuerEpoch && a.SourceUid == b.SourceUid && a.SourceGeneration == b.SourceGeneration && bytes.Equal(a.SourceDigest, b.SourceDigest) && a.Suspended == b.Suspended && a.RecoveryBlocked == b.RecoveryBlocked && a.ObservedAt == b.ObservedAt && a.FreshUntil == b.FreshUntil
}
