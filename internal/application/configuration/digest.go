package configuration

import (
	"cmp"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

// PermissionScopeDigest binds the actual scope and its expiry, not a caller's
// claim that a changed namespace/workload scope is equivalent. Display reasons
// and independent subjects are excluded; their source spec remains provenance.
func PermissionScopeDigest(b value.PermissionBasis) artifact.Digest {
	scope := b.Scope
	scope.Workloads = append([]value.WorkloadRef{}, scope.Workloads...)
	slices.SortFunc(scope.Workloads, func(a, b value.WorkloadRef) int { return cmp.Compare(a.UID, b.UID) })
	wire := struct {
		Scope        value.Scope
		Kind, Effect string
		NotAfter     string
	}{scope, b.Resource.Kind, b.Effect, ""}
	if !b.NotAfter.IsZero() {
		wire.NotAfter = b.NotAfter.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	encoded, _ := json.Marshal(wire)
	c := jsontext.Value(encoded)
	if c.Canonicalize() != nil {
		return artifact.Digest{}
	}
	return artifact.Digest(sha256.Sum256(c))
}
