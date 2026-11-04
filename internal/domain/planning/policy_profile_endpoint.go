package planning

import (
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicyProfileEndpoint is the protected definition and selected binding a
// recurring policy approves. It has no concrete Pod, route, observation time or
// endpoint digest. Normalized acquisition parameters remain in Action.
type PolicyProfileEndpoint struct {
	Definition                         GoEndpointDefinition
	DefinitionDigest                   artifact.Digest
	SourceRef, SourceKind, AddressMode string
	Binding                            *targets.ProfileEndpointBinding `json:",omitempty"`
	Port                               uint16
}

func (p *PolicyProfileEndpoint) Valid() bool {
	if p == nil || !p.Definition.Valid() || p.DefinitionDigest == (artifact.Digest{}) || !GoEndpointReference(p.SourceRef) || !slices.Contains(p.Definition.AddressModes, p.AddressMode) {
		return false
	}
	switch p.SourceKind {
	case targets.ProfileEndpointTemplateBinding:
		return p.Binding != nil && p.Binding.Valid() && p.Binding.Name == p.SourceRef && p.Binding.TemplateRef == p.Definition.Source.Name && p.Binding.AddressMode == p.AddressMode && p.Port == 0
	case targets.ProfileEndpointAdministratorProfile:
		return p.Binding == nil && p.SourceRef == p.Definition.Source.Name && p.Port >= p.Definition.MinimumPort && p.Port <= p.Definition.MaximumPort
	}
	return false
}

func (p *PolicyProfileEndpoint) Clone() *PolicyProfileEndpoint {
	if p == nil {
		return nil
	}
	out := *p
	out.Definition.AddressModes = slices.Clone(p.Definition.AddressModes)
	if p.Definition.TLS != nil {
		t := *p.Definition.TLS
		out.Definition.TLS = &t
	}
	if p.Definition.Credential != nil {
		c := *p.Definition.Credential
		c.Audiences = slices.Clone(c.Audiences)
		out.Definition.Credential = &c
	}
	if p.Binding != nil {
		b := *p.Binding
		out.Binding = &b
	}
	return &out
}

// Matches checks stable reviewed facts against a separately resolved child.
// The caller still checks acquisition parameters and the accepted workload/Pod.
func (p *PolicyProfileEndpoint) Matches(r targets.ProfileEndpointResolution) bool {
	if !p.Valid() || !r.Answers(r.Request) || r.DefinitionDigest != p.DefinitionDigest || r.SourceKind != p.SourceKind || r.SourceName != p.Definition.Source.Name || r.Request.SourceRef != p.SourceRef || r.AddressMode != p.AddressMode || r.PathPolicy != p.Definition.PathPolicy || r.TLS != (p.Definition.TLS != nil) || r.Credential != (p.Definition.Credential != nil) || r.Request.Target.ClusterID != p.Definition.Source.ClusterID || p.Definition.ScopeNamespaceUID != "" && r.Request.Target.Namespace.UID != p.Definition.ScopeNamespaceUID {
		return false
	}
	if c := p.Definition.Credential; c != nil {
		matches := false
		for _, a := range c.Audiences {
			matches = matches || a.Matches(r.Request.Target)
		}
		if !matches {
			return false
		}
	}
	if p.Binding == nil {
		return r.Port == p.Port && r.DeclaredPortName == ""
	}
	return r.DeclaredPortName == p.Binding.PortName && r.Port >= p.Definition.MinimumPort && r.Port <= p.Definition.MaximumPort && slices.Contains(r.Request.Bindings, *p.Binding)
}
