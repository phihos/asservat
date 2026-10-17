package kubernetes

import (
	"context"
	"time"

	port "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// CapacitySource reads complete desired-state lists. SQL acceptance additionally
// requires the independently installed native guards, backend qualification and
// current recovery. A successful read alone grants none of those properties.
type CapacitySource struct {
	client    *PermissionClient
	validator *capacityValidator
}

func NewCapacitySource(client *PermissionClient) (*CapacitySource, error) {
	if client == nil {
		return nil, cfg.ErrInvalid
	}
	v, e := newCapacityValidator()
	if e != nil {
		return nil, e
	}
	return &CapacitySource{client, v}, nil
}

var _ port.CapacitySourceReader = (*CapacitySource)(nil)

func (s *CapacitySource) ReadCapacitySource(ctx context.Context) (port.CapacitySourceObservation, error) {
	var zero port.CapacitySourceObservation
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	start := s.client.now()
	until := start.Add(port.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	ns, e := s.client.namespace(call, s.client.control)
	if e != nil || ns.Deleting {
		return zero, cfg.ErrUnavailable
	}
	budget := 8 << 20
	pRV, pools, pRefs, e := s.client.list(call, "EvidenceStoragePool", "evidencestoragepools", start, &budget)
	if e != nil || len(pools) > port.CapacityPoolLimit {
		return zero, cfg.ErrUnavailable
	}
	bRV, policies, bRefs, e := s.client.list(call, "EvidenceBudgetPolicy", "evidencebudgetpolicies", start, &budget)
	if e != nil || len(policies) > port.CapacityPolicyLimit {
		return zero, cfg.ErrUnavailable
	}
	out := port.CapacitySourceObservation{Snapshot: port.CapacitySnapshot{ClusterID: s.client.clusterID, ControlNamespace: s.client.control, PoolResourceVersion: pRV, PolicyResourceVersion: bRV, ObservedAt: start, FreshUntil: until, Pools: make([]port.PoolObservation, 0, len(pools)), Policies: make([]port.BudgetPolicyObservation, 0, len(policies))}}
	versions := make([]port.CapacitySourceVersion, 0, len(pools)+len(policies))
	appendVersion := func(o permissionObject, r cfg.Resource) error {
		d, e := capacityRawDigest(o)
		if e != nil {
			return e
		}
		versions = append(versions, port.CapacitySourceVersion{Kind: r.Kind, Name: r.Name, UID: r.UID, Generation: r.Generation, Deleting: r.Deleting, Spec: d})
		return nil
	}
	for i, p := range pools {
		if e = appendVersion(p, pRefs[i]); e != nil {
			return zero, e
		}
		out.Snapshot.Pools = append(out.Snapshot.Pools, s.validator.poolObservation(p, pRefs[i]))
	}
	for i, p := range policies {
		if e = appendVersion(p, bRefs[i]); e != nil {
			return zero, e
		}
		out.Snapshot.Policies = append(out.Snapshot.Policies, s.validator.policyObservation(p, bRefs[i]))
	}
	// Resource/list versions stay in the observation. Status-only revisions and
	// unrelated API progress cannot create a new desired-state acceptance.
	out.Versions = versions
	out.Digest, e = port.CapacitySourceDigest(out.Snapshot, versions)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	ns, e = s.client.namespace(call, s.client.control)
	if e != nil || ns.Deleting || s.client.current(call, start, 5*time.Second) != nil || !out.Snapshot.Valid(s.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
