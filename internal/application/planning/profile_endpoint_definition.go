package planning

import (
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type selectedProfileEndpoint struct {
	definition        value.GoEndpointDefinition
	kind, addressMode string
	port              uint16
	binding           *value.GoEndpointBinding
}

// Shared selection stops before observing a Pod's named port or route.
func selectProfileEndpoint(c value.GoEndpointCatalog, cluster, namespace, source string, bindings []value.GoEndpointBinding) (selectedProfileEndpoint, error) {
	var out selectedProfileEndpoint
	if !value.GoEndpointReference(source) || len(bindings) > 16 || len(c.Templates)+len(c.Profiles) > 128 {
		return out, value.ErrProfileEndpointInvalid
	}
	names := map[string]bool{}
	templates := map[string]value.GoEndpointDefinition{}
	profiles := map[string]value.GoEndpointProfile{}
	applicable := func(d value.GoEndpointDefinition) bool {
		return d.Source.ClusterID == cluster && (d.ScopeNamespaceUID == "" || d.ScopeNamespaceUID == namespace)
	}
	for _, d := range c.Templates {
		if !d.Valid() {
			return out, value.ErrProfileEndpointInvalid
		}
		if !applicable(d) {
			continue
		}
		if names[d.Source.Name] {
			return out, value.ErrProfileEndpointAmbiguous
		}
		names[d.Source.Name], templates[d.Source.Name] = true, d
	}
	for _, p := range c.Profiles {
		d := p.Definition
		if !d.Valid() || !slices.Contains(d.AddressModes, p.AddressMode) || p.Port < d.MinimumPort || p.Port > d.MaximumPort {
			return out, value.ErrProfileEndpointInvalid
		}
		if !applicable(d) {
			continue
		}
		if names[d.Source.Name] {
			return out, value.ErrProfileEndpointAmbiguous
		}
		names[d.Source.Name], profiles[d.Source.Name] = true, p
	}
	seen := map[string]bool{}
	var selected *value.GoEndpointBinding
	for _, b := range bindings {
		if !b.Valid() {
			return out, value.ErrProfileEndpointInvalid
		}
		if seen[b.Name] {
			return out, value.ErrProfileEndpointAmbiguous
		}
		seen[b.Name] = true
		if _, found := profiles[b.Name]; found {
			return out, value.ErrProfileEndpointAmbiguous
		}
		if b.Name == source {
			selected = &b
		}
	}
	if selected != nil {
		d, found := templates[selected.TemplateRef]
		if !found {
			return out, value.ErrProfileEndpointUnavailable
		}
		if !slices.Contains(d.AddressModes, selected.AddressMode) {
			return out, value.ErrProfileEndpointDenied
		}
		return selectedProfileEndpoint{definition: cloneProfileDefinition(d), kind: targets.ProfileEndpointTemplateBinding, addressMode: selected.AddressMode, binding: selected}, nil
	}
	if p, found := profiles[source]; found {
		return selectedProfileEndpoint{definition: cloneProfileDefinition(p.Definition), kind: targets.ProfileEndpointAdministratorProfile, addressMode: p.AddressMode, port: p.Port}, nil
	}
	return out, value.ErrProfileEndpointUnavailable
}

// ProfileEndpointDefinitionDigest retains the existing manual definition format.
func ProfileEndpointDefinitionDigest(d value.GoEndpointDefinition) (artifact.Digest, error) {
	if !d.Valid() {
		return artifact.Digest{}, value.ErrProfileEndpointInvalid
	}
	record := struct {
		Format     string                     `json:"format"`
		Definition value.GoEndpointDefinition `json:"definition"`
	}{"asservat-go-profile-definition/v1", cloneProfileDefinition(d)}
	_, digest, err := profileEndpointCanonical(record)
	return digest, err
}

// ResolveProfileEndpointDefinition returns protected public definition metadata,
// with no Pod observation, network operation, credential read or new authority.
func ResolveProfileEndpointDefinition(entries []ProfileEndpointEntry, r targets.ProfileEndpointDefinitionRequest) (targets.ProfileEndpointDefinitionResolution, error) {
	var out targets.ProfileEndpointDefinitionResolution
	if !r.Valid() {
		return out, targets.ErrInvalid
	}
	if len(entries) == 0 {
		return out, targets.ErrUnsupported
	}
	c := profileEndpointCatalog(entries, r.Namespace)
	bindings := make([]value.GoEndpointBinding, 0, len(r.Bindings))
	for _, b := range r.Bindings {
		bindings = append(bindings, value.GoEndpointBinding{Name: b.Name, TemplateRef: b.TemplateRef, AddressMode: b.AddressMode, PortName: b.PortName})
	}
	s, err := selectProfileEndpoint(c, r.ClusterID, r.Namespace.UID, r.SourceRef, bindings)
	if err != nil {
		return out, profileEndpointTargetError(err)
	}
	d := s.definition
	digest, err := ProfileEndpointDefinitionDigest(d)
	if err != nil {
		return out, targets.ErrInvalid
	}
	out = targets.ProfileEndpointDefinitionResolution{Request: r, SourceClusterID: d.Source.ClusterID, SourceNamespaceUID: d.Source.NamespaceUID, SourceUID: d.Source.ResourceUID, SourceName: d.Source.Name, SourceDigest: d.Source.Digest, DefinitionDigest: digest,
		ScopeNamespaceUID: d.ScopeNamespaceUID, Host: d.Host, PathPolicy: d.PathPolicy, LoopbackFamily: d.LoopbackFamily, AddressModes: slices.Clone(d.AddressModes), MinimumPort: d.MinimumPort, MaximumPort: d.MaximumPort, SourceKind: s.kind, AddressMode: s.addressMode, Port: s.port}
	if d.TLS != nil {
		t := d.TLS
		out.TLS = targets.ProfileEndpointTLSDefinition{TrustClusterID: t.Trust.ClusterID, TrustNamespaceUID: t.Trust.NamespaceUID, TrustUID: t.Trust.ResourceUID, TrustName: t.Trust.Name, TrustDigest: t.Trust.Digest, ServerName: t.ServerName}
	}
	if c := d.Credential; c != nil {
		out.Credential = &targets.ProfileEndpointCredentialDefinition{PolicyClusterID: c.Policy.ClusterID, PolicyNamespaceUID: c.Policy.NamespaceUID, PolicyUID: c.Policy.ResourceUID, PolicyName: c.Policy.Name, PolicyDigest: c.Policy.Digest}
		for _, a := range c.Audiences {
			out.Credential.Audiences = append(out.Credential.Audiences, targets.ProfileEndpointCredentialAudience{ClusterID: a.ClusterID, NamespaceUID: a.NamespaceUID, WorkloadKind: a.WorkloadKind, WorkloadUID: a.WorkloadUID})
		}
	}
	if s.binding != nil {
		out.Binding = &targets.ProfileEndpointBinding{Name: s.binding.Name, TemplateRef: s.binding.TemplateRef, AddressMode: s.binding.AddressMode, PortName: s.binding.PortName}
	}
	if !out.Answers(r) {
		return targets.ProfileEndpointDefinitionResolution{}, targets.ErrInvalid
	}
	return out.Clone(), nil
}

// PolicyProfileEndpointFromResolution checks the complete public
// definition against its digest before storing it in a target-independent scope.
func PolicyProfileEndpointFromResolution(a targets.ProfileEndpointDefinitionResolution) (*value.PolicyProfileEndpoint, error) {
	if !a.Answers(a.Request) {
		return nil, value.ErrInvalid
	}
	d := value.GoEndpointDefinition{ScopeNamespaceUID: a.ScopeNamespaceUID, Source: value.GoEndpointSource{ClusterID: a.SourceClusterID, NamespaceUID: a.SourceNamespaceUID, ResourceUID: a.SourceUID, Name: a.SourceName, Digest: a.SourceDigest}, Host: a.Host, PathPolicy: a.PathPolicy, LoopbackFamily: a.LoopbackFamily, AddressModes: slices.Clone(a.AddressModes), MinimumPort: a.MinimumPort, MaximumPort: a.MaximumPort}
	if !a.TLS.IsZero() {
		t := a.TLS
		d.TLS = &value.GoEndpointTLS{Trust: value.GoEndpointSource{ClusterID: t.TrustClusterID, NamespaceUID: t.TrustNamespaceUID, ResourceUID: t.TrustUID, Name: t.TrustName, Digest: t.TrustDigest}, ServerName: t.ServerName}
	}
	if c := a.Credential; c != nil {
		d.Credential = &value.GoEndpointCredential{Policy: value.GoEndpointSource{ClusterID: c.PolicyClusterID, NamespaceUID: c.PolicyNamespaceUID, ResourceUID: c.PolicyUID, Name: c.PolicyName, Digest: c.PolicyDigest}}
		for _, a := range c.Audiences {
			d.Credential.Audiences = append(d.Credential.Audiences, value.GoEndpointAudience{ClusterID: a.ClusterID, NamespaceUID: a.NamespaceUID, WorkloadKind: a.WorkloadKind, WorkloadUID: a.WorkloadUID})
		}
	}
	digest, err := ProfileEndpointDefinitionDigest(d)
	if err != nil || digest != a.DefinitionDigest {
		return nil, value.ErrInvalid
	}
	out := &value.PolicyProfileEndpoint{Definition: d, DefinitionDigest: digest, SourceRef: a.Request.SourceRef, SourceKind: a.SourceKind, AddressMode: a.AddressMode, Binding: a.Binding, Port: a.Port}
	if !out.Valid() {
		return nil, value.ErrInvalid
	}
	return out.Clone(), nil
}
