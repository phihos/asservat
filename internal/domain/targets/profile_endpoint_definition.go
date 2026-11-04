package targets

import (
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// ProfileEndpointDefinitionRequest selects protected endpoint metadata without
// a Pod. Workload authority is checked independently by policy acceptance.
type ProfileEndpointDefinitionRequest struct {
	ClusterID string
	Namespace configuration.NamespaceRef
	SourceRef string
	Bindings  []ProfileEndpointBinding `json:",omitempty"`
}

func (r ProfileEndpointDefinitionRequest) Valid() bool {
	if !authorization.UUID(r.ClusterID) || !identity.Text(r.Namespace.Name, 63) || !identity.Text(r.Namespace.UID, 64) || !identity.Text(r.SourceRef, 63) || len(r.Bindings) > MaxProfileEndpointBindings {
		return false
	}
	seen := map[string]bool{}
	for _, b := range r.Bindings {
		if !b.Valid() || seen[b.Name] {
			return false
		}
		seen[b.Name] = true
	}
	return true
}

func (r ProfileEndpointDefinitionRequest) Equal(o ProfileEndpointDefinitionRequest) bool {
	return r.ClusterID == o.ClusterID && r.Namespace == o.Namespace && r.SourceRef == o.SourceRef && slices.Equal(r.Bindings, o.Bindings)
}

// ProfileEndpointDefinitionResolution carries only the currently qualified
// uncredentialed definition. A TLS/credential definition must be refused, not
// projected without its dependencies. It contains no route or freshness dates.
type ProfileEndpointDefinitionResolution struct {
	Request                                                    ProfileEndpointDefinitionRequest
	SourceClusterID, SourceNamespaceUID, SourceUID, SourceName string
	SourceDigest, DefinitionDigest                             artifact.Digest
	ScopeNamespaceUID, Host, PathPolicy, LoopbackFamily        string
	AddressModes                                               []string
	MinimumPort, MaximumPort                                   uint16
	SourceKind, AddressMode                                    string
	Binding                                                    *ProfileEndpointBinding `json:",omitempty"`
	Port                                                       uint16
}

func (a ProfileEndpointDefinitionResolution) Clone() ProfileEndpointDefinitionResolution {
	a.Request.Bindings = slices.Clone(a.Request.Bindings)
	a.AddressModes = slices.Clone(a.AddressModes)
	if a.Binding != nil {
		b := *a.Binding
		a.Binding = &b
	}
	return a
}

func (a ProfileEndpointDefinitionResolution) Answers(r ProfileEndpointDefinitionRequest) bool {
	if !r.Valid() || !a.Request.Equal(r) || a.SourceClusterID != r.ClusterID || !authorization.UUID(a.SourceUID) || a.SourceNamespaceUID != "" && !authorization.UUID(a.SourceNamespaceUID) || !identity.Text(a.SourceName, 63) || a.SourceDigest == (artifact.Digest{}) || a.DefinitionDigest == (artifact.Digest{}) || a.ScopeNamespaceUID != "" && a.ScopeNamespaceUID != r.Namespace.UID || !identity.Text(a.Host, 253) || a.PathPolicy != "go-pprof/v1" || a.MinimumPort == 0 || a.MaximumPort < a.MinimumPort || len(a.AddressModes) < 1 || len(a.AddressModes) > 2 || !slices.Contains(a.AddressModes, a.AddressMode) {
		return false
	}
	for i, mode := range a.AddressModes {
		if mode != "targetLoopback" && mode != "podIP" || slices.Contains(a.AddressModes[:i], mode) {
			return false
		}
	}
	if slices.Contains(a.AddressModes, "targetLoopback") {
		if a.LoopbackFamily != "ipv4" && a.LoopbackFamily != "ipv6" {
			return false
		}
	} else if a.LoopbackFamily != "" {
		return false
	}
	switch a.SourceKind {
	case ProfileEndpointTemplateBinding:
		return a.Binding != nil && a.Binding.Valid() && a.Binding.Name == r.SourceRef && a.Binding.TemplateRef == a.SourceName && a.Binding.AddressMode == a.AddressMode && a.Port == 0 && slices.Contains(r.Bindings, *a.Binding)
	case ProfileEndpointAdministratorProfile:
		return a.Binding == nil && r.SourceRef == a.SourceName && a.Port >= a.MinimumPort && a.Port <= a.MaximumPort
	}
	return false
}
