package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"maps"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

const ProtectedPoolPlanFormat = "capacity-pool/v1"
const ProtectedPoolPlanBytes = 64 << 10

// This is the closed complete-pool arithmetic plan. Backend qualification,
// per-account child costs and current authority are deliberately separate;
// these quantities alone cannot reserve storage or publish a workload binding.
// SQL54 recomputes the same plan from its locked accepted source.
type ProtectedPoolPlan struct {
	Format, Name, UID                          string
	Generation                                 int64
	Digest                                     artifact.Digest
	StorageProfile                             string
	Capacity, Safety, System, Burst, Protected BudgetAmount
	AccountLimit, NamespaceLimit               int64
	Policies                                   []ProtectedPolicyPlan
	Clusters                                   []ProtectedClusterPlan
}
type ProtectedPolicyPlan struct {
	Name, UID  string
	Generation int64
	Digest     artifact.Digest
	Scope      BudgetScope
	Budget     PolicyBudgetInput
	Slots      int64
}
type ProtectedClusterPlan struct {
	ClusterID                                                              string
	ProtectedBytes, ProtectedObjects, ByteLimit, ObjectLimit, AccountLimit int64
}

func CompileProtectedPoolPlan(source CapacitySnapshot, poolName string) (ProtectedPoolPlan, error) {
	var zero ProtectedPoolPlan
	// Includes all policies assigned to this pool, even when today's workload
	// matches only one. It also checks the canonical identity/decoded pairing.
	if _, e := SelectedCapacitySourceDigest(source, poolName); e != nil {
		return zero, e
	}
	var pool *PoolObservation
	for i := range source.Pools {
		if source.Pools[i].Resource.Name == poolName {
			pool = &source.Pools[i]
			break
		}
	}
	if pool == nil || pool.Budget == nil {
		return zero, cfg.ErrUnavailable
	}
	input := make([]PolicyBudgetInput, 0, len(source.Policies))
	refs := map[string]BudgetPolicyObservation{}
	for _, p := range source.Policies {
		if p.Pool == poolName {
			input = append(input, *p.Budget)
			refs[p.Resource.Name] = p
		}
	}
	compiled, e := CompileProtectedPool(*pool.Budget, input)
	if e != nil {
		return zero, e
	}
	out := ProtectedPoolPlan{Format: ProtectedPoolPlanFormat, Name: pool.Resource.Name, UID: pool.Resource.UID, Generation: pool.Resource.Generation, Digest: pool.Resource.SpecDigest, StorageProfile: pool.StorageProfile,
		Capacity: compiled.capacity, Safety: compiled.safety, System: compiled.system, Burst: compiled.burst, Protected: compiled.protected, AccountLimit: compiled.slots, NamespaceLimit: compiled.slots,
		Policies: make([]ProtectedPolicyPlan, 0, len(refs)), Clusters: make([]ProtectedClusterPlan, 0, len(compiled.clusters))}
	for _, name := range compiled.PolicyNames() {
		p := refs[name]
		b := compiled.policies[name]
		out.Policies = append(out.Policies, ProtectedPolicyPlan{Name: name, UID: p.Resource.UID, Generation: p.Resource.Generation, Digest: p.Resource.SpecDigest, Scope: BudgetScope{p.Scope.ClusterID, maps.Clone(p.Scope.NamespaceLabels)}, Budget: b.input, Slots: b.slots})
	}
	ids := make([]string, 0, len(compiled.clusters))
	for id := range compiled.clusters {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		c := compiled.clusters[id]
		limit, count, e := compiled.ClusterCeiling(id)
		if e != nil {
			return zero, e
		}
		out.Clusters = append(out.Clusters, ProtectedClusterPlan{ClusterID: id, ProtectedBytes: c.protected.Bytes, ProtectedObjects: c.protected.Objects, ByteLimit: limit.Bytes, ObjectLimit: limit.Objects, AccountLimit: count})
	}
	if b, e := json.Marshal(out); e != nil || len(b) > ProtectedPoolPlanBytes {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

// CanonicalProtectedPoolPlan binds only the closed compiler output. It cannot
// bless a mutated exported DTO: callers supply the independently read snapshot
// and the plan is recomputed here. SQL compares the complete normalized object,
// while the versioned digest binds these original Go JSON bytes on replay.
func CanonicalProtectedPoolPlan(source CapacitySnapshot, poolName string) ([]byte, artifact.Digest, error) {
	plan, e := CompileProtectedPoolPlan(source, poolName)
	if e != nil {
		return nil, artifact.Digest{}, e
	}
	b, e := json.Marshal(plan)
	if e != nil || len(b) > ProtectedPoolPlanBytes {
		return nil, artifact.Digest{}, cfg.ErrUnavailable
	}
	h := sha256.New()
	_, _ = h.Write([]byte("asservat-capacity-pool/json-v1\x00"))
	_, _ = h.Write(b)
	var digest artifact.Digest
	copy(digest[:], h.Sum(nil))
	return b, digest, nil
}
