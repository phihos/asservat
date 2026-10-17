package postgres

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	configuration "asservat.local/asservat/internal/application/configuration"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// RetentionTransactionGuard is private role composition, never request input.
// Observe topology before taking SQL locks; check the original proof and current
// source rows INSIDE the effect transaction, after all blocking work. A separate
// preflight transaction cannot close the check/use race.
type RetentionTransactionGuard struct {
	root     string
	topology configuration.RetentionTopologyReader
}

func NewRetentionTransactionGuard(root string, topology configuration.RetentionTopologyReader) (*RetentionTransactionGuard, error) {
	if !authorization.UUID(root) || topology == nil {
		return nil, artifact.ErrInvalid
	}
	return &RetentionTransactionGuard{root: root, topology: topology}, nil
}
func (g *RetentionTransactionGuard) observe(ctx context.Context, cluster string) (privacy.PolicyTopology, error) {
	if g == nil || g.topology == nil || !authorization.UUID(cluster) {
		return privacy.PolicyTopology{}, privacyapp.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	t, err := g.topology.RetentionTopology(ctx, cluster)
	if err != nil || !t.Valid(time.Now()) || t.RootID != g.root || t.TargetClusterID != cluster {
		return privacy.PolicyTopology{}, privacyapp.ErrUnavailable
	}
	t.Sources = slices.Clone(t.Sources)
	slices.SortFunc(t.Sources, func(a, b privacy.PolicySourceRef) int {
		if a.Hub != b.Hub {
			if a.Hub {
				return -1
			}
			return 1
		}
		return 0
	})
	return t, nil
}
func (g *RetentionTransactionGuard) check(ctx context.Context, q *custodydb.Queries, t privacy.PolicyTopology, p artifact.RetentionProof, target authorization.Target) error {
	if g == nil {
		return privacyapp.ErrUnavailable
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !t.Valid(now.Time) || !p.Valid(now.Time) || !p.Matches(g.root, target.ClusterID, target.NamespaceUID, target.WorkloadUID, target.PodUID) || t.RootID != g.root || p.RootID != g.root || p.Topology != t.Revision || p.ClusterID != t.TargetClusterID || p.SourceCount != len(t.Sources) {
		return privacyapp.ErrFence
	}
	until := identity.Earlier(t.FreshUntil, p.ValidUntil)
	for i, ref := range t.Sources {
		v := p.Sources[i]
		if v.ClusterID != ref.ClusterID || v.ControlNamespaceUID != ref.ControlNamespaceUID || v.Hub != ref.Hub || v.ProtectionDigest != ref.ProtectionDigest {
			return privacyapp.ErrFence
		}
		s, err := acceptedRetentionSource(ctx, q, g.root, ref)
		if err != nil {
			return err
		}
		if s.Epoch != v.Epoch || s.Acceptance != v.Acceptance || artifact.Digest(s.Snapshot.Revision.Digest) != v.SnapshotDigest {
			return privacyapp.ErrFence
		}
		until = identity.Earlier(until, identity.Earlier(s.FreshUntil, s.Snapshot.FreshUntil))
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !now.Time.Before(until) {
		return privacyapp.ErrExpired
	}
	return nil
}
