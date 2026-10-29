package capacity

import (
	"context"
	"maps"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	CapacityPoolLimit      = 16
	CapacityPolicyLimit    = 64
	CapacitySourceInterval = 5 * time.Second
)

// Scope is decoded independently of the remaining budget fields. A malformed
// scope is unknown, never a nonmatching scope. Invalid desired settings outside
// a completely understood scope need not disable an unrelated pool.
type BudgetScope struct {
	ClusterID       string
	NamespaceLabels map[string]string
}

func (s BudgetScope) valid() bool {
	if !authorization.UUID(s.ClusterID) || len(s.NamespaceLabels) < 1 || len(s.NamespaceLabels) > 16 {
		return false
	}
	for k, v := range s.NamespaceLabels {
		if !identity.Text(k, 253) || !identity.Text(v, 63) {
			return false
		}
	}
	return true
}

type PoolObservation struct {
	Resource                  cfg.Resource
	StorageProfile, Assurance string
	// Nil means full schema/semantic decoding failed. Exact metadata is retained
	// so a different pool can still be selected from the complete list.
	Budget *PoolBudgetInput
}

// SourceResourceLimits are optional administrator lowering observations. They
// remain separate from the immutable storage budget and never grant acquisition.
type SourceResourceLimits struct {
	Node     collector.PolicyLimits
	Workload collector.SourceLimits
}

type BudgetPolicyObservation struct {
	SourceResources *SourceResourceLimits `json:",omitempty"`
	Resource        cfg.Resource
	Scope           *BudgetScope
	Pool            string
	Budget          *PolicyBudgetInput
}

// Snapshot preserves complete per-kind LIST revisions. It is not an atomic
// Kubernetes transaction, accepted source, backend qualification or effect proof.
type CapacitySnapshot struct {
	ClusterID                                  string
	ControlNamespace                           cfg.NamespaceRef
	PoolResourceVersion, PolicyResourceVersion string
	ObservedAt, FreshUntil                     time.Time
	Pools                                      []PoolObservation
	Policies                                   []BudgetPolicyObservation
}
type CapacitySourceObservation struct {
	Snapshot CapacitySnapshot
	Versions []CapacitySourceVersion
	Digest   artifact.Digest
}
type CapacitySourceReader interface {
	ReadCapacitySource(context.Context) (CapacitySourceObservation, error)
}

func capacityResource(r cfg.Resource, s CapacitySnapshot, kind string) bool {
	return r.ClusterID == s.ClusterID && r.Namespace == s.ControlNamespace.Name && r.NamespaceUID == s.ControlNamespace.UID && r.Kind == kind && identity.Text(r.Name, 63) && identity.Text(r.UID, 64) && identity.Text(r.ResourceVersion, 128) && r.Generation > 0 && r.Generation <= 2147483647
}
func (s CapacitySnapshot) Valid(now time.Time) bool {
	if !authorization.UUID(s.ClusterID) || !identity.Text(s.ControlNamespace.Name, 63) || !identity.Text(s.ControlNamespace.UID, 64) || !identity.Text(s.PoolResourceVersion, 128) || !identity.Text(s.PolicyResourceVersion, 128) || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, CapacitySourceInterval) || len(s.Pools) > CapacityPoolLimit || len(s.Policies) > CapacityPolicyLimit {
		return false
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, p := range s.Pools {
		if !capacityResource(p.Resource, s, "EvidenceStoragePool") || ids[p.Resource.UID] || names[p.Resource.Name] {
			return false
		}
		ids[p.Resource.UID], names[p.Resource.Name] = true, true
	}
	names = map[string]bool{}
	for _, p := range s.Policies {
		if p.SourceResources != nil && (!p.SourceResources.Node.Valid() || !p.SourceResources.Workload.Valid()) {
			return false
		}
		if !capacityResource(p.Resource, s, "EvidenceBudgetPolicy") || ids[p.Resource.UID] || names[p.Resource.Name] {
			return false
		}
		ids[p.Resource.UID], names[p.Resource.Name] = true, true
	}
	return true
}

// SelectedBudget contains only the pool and selected policy. Other policies
// contribute protected commitments to its compiled pool without being exposed
// to evidence callers. SQL still verifies current accepted source and backing.
type SelectedBudget struct {
	Pool, Policy           cfg.Resource
	StorageProfile         string
	Scope                  BudgetScope
	Budget                 PolicyBudgetInput
	Compiled               CompiledPoolBudget
	ObservedAt, FreshUntil time.Time
}

// SelectBudget uses a complete independently protected namespace observation.
// protectedKeys is supplied by the installed metadata guard, never by policy
// status or the request. A missing protected label is a known absence only
// because that complete key set was actually read by the concrete observer.
func SelectBudget(s CapacitySnapshot, ns cfg.NamespaceMetadata, protectedKeys []string, now time.Time) (SelectedBudget, error) {
	var zero SelectedBudget
	if !s.Valid(now) || !authorization.UUID(ns.ClusterID) || ns.Deleting || !identity.Text(ns.Namespace.Name, 63) || !identity.Text(ns.Namespace.UID, 64) || !identity.Text(ns.ResourceVersion, 128) || !identity.Fresh(ns.ObservedAt, ns.FreshUntil, now, CapacitySourceInterval) || len(protectedKeys) < 1 || len(protectedKeys) > 256 {
		return zero, cfg.ErrUnavailable
	}
	keys := map[string]bool{}
	for _, k := range protectedKeys {
		if !identity.Text(k, 253) || keys[k] {
			return zero, ErrBudgetInvalid
		}
		keys[k] = true
	}
	var selected *BudgetPolicyObservation
	for i := range s.Policies {
		p := &s.Policies[i]
		if p.Scope == nil || !p.Scope.valid() {
			return zero, cfg.ErrUnavailable
		}
		if p.Scope.ClusterID != ns.ClusterID {
			continue
		}
		match := true
		for k, v := range p.Scope.NamespaceLabels {
			if !keys[k] {
				return zero, cfg.ErrUnavailable
			}
			if actual, ok := ns.Labels[k]; !ok || actual != v {
				match = false
			}
		}
		if !match {
			continue
		}
		if selected != nil {
			return zero, ErrAmbiguousBudgetProfile
		}
		selected = p
	}
	if selected == nil {
		return zero, ErrCapacityNotAllocated
	}
	if selected.Resource.Deleting || selected.Resource.SpecDigest == (artifact.Digest{}) || selected.Budget == nil || selected.Budget.Name != selected.Resource.Name || selected.Budget.Pool != selected.Pool || selected.Budget.Cluster != ns.ClusterID {
		return zero, cfg.ErrUnavailable
	}
	var pool *PoolObservation
	for i := range s.Pools {
		if s.Pools[i].Resource.Name == selected.Pool {
			pool = &s.Pools[i]
			break
		}
	}
	if pool == nil || pool.Resource.Deleting || pool.Resource.SpecDigest == (artifact.Digest{}) || pool.Budget == nil || pool.Budget.Name != pool.Resource.Name || pool.Assurance != "qualifiedReservedBackend" || !identity.Text(pool.StorageProfile, 63) {
		return zero, cfg.ErrUnavailable
	}
	inputs := make([]PolicyBudgetInput, 0, len(pool.Budget.Slots))
	for _, p := range s.Policies {
		if p.Pool != pool.Resource.Name {
			continue
		}
		if p.Resource.Deleting || p.Resource.SpecDigest == (artifact.Digest{}) || p.Scope == nil || !p.Scope.valid() || p.Budget == nil || p.Budget.Name != p.Resource.Name || p.Budget.Pool != p.Pool || p.Budget.Cluster != p.Scope.ClusterID {
			return zero, cfg.ErrUnavailable
		}
		inputs = append(inputs, *p.Budget)
	}
	compiled, err := CompileProtectedPool(*pool.Budget, inputs)
	if err != nil {
		return zero, err
	}
	start := s.ObservedAt
	if ns.ObservedAt.After(start) {
		start = ns.ObservedAt
	}
	until := identity.Earlier(s.FreshUntil, ns.FreshUntil)
	if !identity.Fresh(start, until, now, CapacitySourceInterval) {
		return zero, cfg.ErrUnavailable
	}
	return SelectedBudget{Pool: pool.Resource, Policy: selected.Resource, StorageProfile: pool.StorageProfile, Scope: BudgetScope{selected.Scope.ClusterID, maps.Clone(selected.Scope.NamespaceLabels)}, Budget: *selected.Budget, Compiled: compiled, ObservedAt: start, FreshUntil: until}, nil
}

// The permanent key contains actual immutable identities only. Display names,
// policy selection, labels and accepted source revisions cannot mint a new
// account. A replacement workload UID remains a distinct, parent-charged row.
type WorkloadCapacityKey struct{ RootID, ClusterID, NamespaceUID, WorkloadUID string }

func (k WorkloadCapacityKey) Valid() bool {
	return authorization.UUID(k.RootID) && authorization.UUID(k.ClusterID) && identity.Text(k.NamespaceUID, 64) && identity.Text(k.WorkloadUID, 64)
}
