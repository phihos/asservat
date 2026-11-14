package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
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
	// Fixed steps name the refusing check; every failure stays unavailable.
	step := func(name string, e error) error {
		return &observationStep{name, errors.Join(cfg.ErrUnavailable, e)}
	}
	ns, e := s.client.namespace(call, s.client.control)
	if e != nil || ns.Deleting {
		return zero, step("namespace", e)
	}
	budget := 8 << 20
	pRV, pools, pRefs, _, e := s.client.list(call, "EvidenceStoragePool", "evidencestoragepools", start, &budget)
	if e != nil || len(pools) > port.CapacityPoolLimit {
		return zero, step("pools", e)
	}
	bRV, policies, bRefs, _, e := s.client.list(call, "EvidenceBudgetPolicy", "evidencebudgetpolicies", start, &budget)
	if e != nil || len(policies) > port.CapacityPolicyLimit {
		return zero, step("policies", e)
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
			return zero, step("pool-spec", e)
		}
		out.Snapshot.Pools = append(out.Snapshot.Pools, s.validator.poolObservation(p, pRefs[i]))
	}
	for i, p := range policies {
		// The version digest and the observation both use the hub-scoped
		// spec, so a Helm-rendered policy without scope.clusterID matches.
		p = hubScopedPolicy(p, s.client.clusterID)
		if e = appendVersion(p, bRefs[i]); e != nil {
			return zero, step("policy-spec", e)
		}
		out.Snapshot.Policies = append(out.Snapshot.Policies, s.validator.policyObservation(p, bRefs[i]))
	}
	// Resource/list versions stay in the observation. Status-only revisions and
	// unrelated API progress cannot create a new desired-state acceptance.
	out.Versions = versions
	out.Digest, e = port.CapacitySourceDigest(out.Snapshot, versions)
	if e != nil {
		return zero, step("digest", e)
	}
	ns, e = s.client.namespace(call, s.client.control)
	if e != nil || ns.Deleting {
		return zero, step("namespace", e)
	}
	if e = s.client.current(call, start, 5*time.Second); e != nil {
		return zero, step("current", e)
	}
	if !out.Snapshot.Valid(s.client.now()) {
		return zero, step("snapshot", nil)
	}
	return out, nil
}

// hubScopedPolicy reads an EvidenceBudgetPolicy whose scope.clusterID is
// empty or absent as scoped to this (hub) cluster: Helm renders the policy
// before the generated cluster ID exists. Malformed or duplicate-key specs
// are left unchanged for the validator to reject.
func hubScopedPolicy(o permissionObject, cluster string) permissionObject {
	if permissionJSON(o.Spec, 64<<10, 16384) != nil {
		return o
	}
	var spec map[string]json.RawMessage
	if json.Unmarshal(o.Spec, &spec) != nil {
		return o
	}
	var scope map[string]json.RawMessage
	if json.Unmarshal(spec["scope"], &scope) != nil || scope == nil {
		return o
	}
	if v, ok := scope["clusterID"]; ok && string(v) != `""` {
		return o
	}
	scope["clusterID"], _ = json.Marshal(cluster)
	var e error
	if spec["scope"], e = json.Marshal(scope); e != nil {
		return o
	}
	b, e := json.Marshal(spec)
	if e != nil {
		return o
	}
	o.Spec = b
	return o
}
