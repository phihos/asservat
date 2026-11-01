package kubernetes

import (
	"asservat.local/asservat/internal/domain/collector"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"

	wire "asservat.local/asservat/api/v1alpha1"
	port "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/util/validation"
)

//go:embed capacity-schemas/*.json
var capacitySchemas embed.FS

type capacityValidator struct{ pool, policy, scope *jsonschema.Schema }

func newCapacityValidator() (*capacityValidator, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(permissionLoader{})
	c.AssertFormat()
	files, e := capacitySchemas.ReadDir("capacity-schemas")
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	for _, f := range files {
		b, e := capacitySchemas.ReadFile("capacity-schemas/" + f.Name())
		if e != nil {
			return nil, cfg.ErrUnavailable
		}
		var v map[string]any
		if json.Unmarshal(b, &v) != nil {
			return nil, cfg.ErrUnavailable
		}
		id, ok := v["$id"].(string)
		if !ok || c.AddResource(id, v) != nil {
			return nil, cfg.ErrUnavailable
		}
	}
	pool, e := c.Compile("https://asservat.io/spec/v1/storage-pool.schema.json#/properties/spec")
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	policy, e := c.Compile("https://asservat.io/spec/v1/budget-policy.schema.json#/properties/spec")
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	scope, e := c.Compile("https://asservat.io/spec/v1/budget-policy.schema.json#/properties/spec/properties/scope")
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	return &capacityValidator{pool, policy, scope}, nil
}
func capacityAmount(w wire.CapacityAmount) port.BudgetAmount {
	return port.BudgetAmount{Bytes: w.Bytes, Objects: w.Objects}
}

func (v *capacityValidator) poolObservation(o permissionObject, r cfg.Resource) port.PoolObservation {
	out := port.PoolObservation{Resource: r}
	var w wire.EvidenceStoragePoolSpec
	digest, e := decodePermissionSpec(o.Spec, v.pool, &w)
	if e != nil || len(validation.IsDNS1123Label(w.StorageProfileRef)) != 0 {
		return out
	}
	b := port.PoolBudgetInput{Name: r.Name, Capacity: capacityAmount(w.Capacity), Safety: capacityAmount(w.SafetyHeadroom), System: capacityAmount(w.SystemReserve), Burst: capacityAmount(w.SharedBurst)}
	for _, slot := range w.ProtectedAllocations {
		if len(validation.IsDNS1123Label(slot.BudgetPolicyRef)) != 0 {
			return out
		}
		b.Slots = append(b.Slots, port.ProtectedSlotInput{Policy: slot.BudgetPolicyRef, Workloads: slot.WorkloadSlots, Protected: capacityAmount(slot.ProtectedPerWorkload)})
	}
	out.Resource.SpecDigest = digest
	out.StorageProfile, out.Assurance, out.Budget = w.StorageProfileRef, w.CapacityAssurance, &b
	return out
}

func (v *capacityValidator) policyObservation(o permissionObject, r cfg.Resource) port.BudgetPolicyObservation {
	out := port.BudgetPolicyObservation{Resource: r}
	// Syntax is checked before extracting matching fields. Duplicate/case-aliased
	// fields, excessive depth and incomplete JSON cannot become safe exclusions.
	if permissionJSON(o.Spec, 64<<10, 16384) != nil {
		return out
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(o.Spec, &fields) != nil {
		return out
	}
	var scope wire.CapacityPolicyScope
	if _, e := decodePermissionSpec(fields["scope"], v.scope, &scope); e != nil || !selectorValid(scope.NamespaceSelector.MatchLabels) {
		return out
	}
	out.Scope = &port.BudgetScope{ClusterID: scope.ClusterID, NamespaceLabels: scope.NamespaceSelector.MatchLabels}
	var pool string
	if json.Unmarshal(fields["poolRef"], &pool) == nil && len(validation.IsDNS1123Label(pool)) == 0 {
		out.Pool = pool
	}
	var w wire.EvidenceBudgetPolicySpec
	digest, e := decodePermissionSpec(o.Spec, v.policy, &w)
	if e != nil || out.Pool == "" || w.PoolRef != out.Pool || w.Scope.ClusterID != scope.ClusterID || len(validation.IsDNS1123Label(w.Node.ImpactProfileRef)) != 0 {
		return out
	}
	out.Resource.SpecDigest = digest
	out.Budget = &port.PolicyBudgetInput{Name: r.Name, Pool: w.PoolRef, Cluster: w.Scope.ClusterID, Protected: capacityAmount(w.Workload.Protected), Hard: capacityAmount(w.Workload.HardLimit), Context: capacityAmount(w.Workload.ContextReserve), NamespaceMaximum: port.BudgetAmount{Bytes: w.NamespaceEnvelope.MaxStoredBytes, Objects: w.NamespaceEnvelope.MaxObjects}, NamespaceAccounts: w.NamespaceEnvelope.MaxWorkloadAccounts}
	if w.Node.MaxActiveSources != 0 || w.Node.InputBytesPerSecond != 0 || w.Node.InputBurstBytes != 0 || w.Workload.MaxActiveSources != 0 || w.Workload.InputBytesPerSecond != 0 || w.Workload.InputBurstBytes != 0 || w.Node.MaxRingBytes != 0 || w.Node.MaxFrozenBytes != 0 {
		out.SourceResources = &port.SourceResourceLimits{Node: collector.PolicyLimits{RingBytes: w.Node.MaxRingBytes, FrozenBytes: w.Node.MaxFrozenBytes, SourceLimits: collector.SourceLimits{MaxActiveSources: w.Node.MaxActiveSources, InputBytesPerSecond: w.Node.InputBytesPerSecond, InputBurstBytes: w.Node.InputBurstBytes}}, Workload: collector.SourceLimits{MaxActiveSources: w.Workload.MaxActiveSources, InputBytesPerSecond: w.Workload.InputBytesPerSecond, InputBurstBytes: w.Workload.InputBurstBytes}}
	}
	return out
}

// Invalid objects also contribute their canonical raw spec digests. A source
// replacement or invalidating edit cannot masquerade as an identical snapshot.
// It carries no raw spec outside C21; opaque RVs stay in the observation.
func capacityRawDigest(o permissionObject) (artifact.Digest, error) {
	if permissionJSON(o.Spec, 64<<10, 16384) != nil {
		return artifact.Digest{}, cfg.ErrUnavailable
	}
	b := jsontext.Value(bytes.Clone(o.Spec))
	if b.Canonicalize() != nil {
		return artifact.Digest{}, cfg.ErrUnavailable
	}
	return sha256.Sum256(b), nil
}
