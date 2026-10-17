package planning

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

// ResolveGoProfileEndpoint is pure resolution, without probing, credential
// retrieval, authorization, admission or network I/O. Catalog values must come
// from the independent protected/current configuration path, never a capture
// caller. This function cannot establish that source acceptance itself.
func ResolveGoProfileEndpoint(in value.GoEndpointInput, now time.Time) (value.GoEndpointPlan, error) {
	var out value.GoEndpointPlan
	if !value.GoEndpointReference(in.SourceRef) || !in.Parameters.Valid() || in.NativeLimit < 1 || len(in.Bindings) > 16 || !in.Network.Valid(now) || !now.Before(in.Deadline) || !identity.Fresh(in.Catalog.ObservedAt, in.Catalog.FreshUntil, now, 5*time.Second) {
		return out, value.ErrProfileEndpointInvalid
	}
	cap := execution.MaximumGoProfileBytes
	if in.Parameters.Type == "runtimeTrace" {
		cap = execution.MaximumGoTraceBytes
	}
	if in.NativeLimit > cap || len(in.Catalog.Templates)+len(in.Catalog.Profiles) > 128 {
		return out, value.ErrProfileEndpointInvalid
	}
	if in.Network.HostNetwork {
		return out, value.ErrProfileHostNetwork
	}
	names := map[string]bool{}
	templates := map[string]value.GoEndpointDefinition{}
	profiles := map[string]value.GoEndpointProfile{}
	for _, d := range in.Catalog.Templates {
		if !d.Valid() {
			return out, value.ErrProfileEndpointInvalid
		}
		if !profileDefinitionApplicable(d, in) {
			continue
		}
		if names[d.Source.Name] {
			return out, value.ErrProfileEndpointAmbiguous
		}
		names[d.Source.Name], templates[d.Source.Name] = true, d
	}
	for _, p := range in.Catalog.Profiles {
		if !p.Definition.Valid() {
			return out, value.ErrProfileEndpointInvalid
		}
		if !slices.Contains(p.Definition.AddressModes, p.AddressMode) || p.Port < p.Definition.MinimumPort || p.Port > p.Definition.MaximumPort {
			return out, value.ErrProfileEndpointInvalid
		}
		if !profileDefinitionApplicable(p.Definition, in) {
			continue
		}
		name := p.Definition.Source.Name
		if names[name] {
			return out, value.ErrProfileEndpointAmbiguous
		}
		names[name], profiles[name] = true, p
	}
	bindings := map[string]value.GoEndpointBinding{}
	for _, b := range in.Bindings {
		if !b.Valid() {
			return out, value.ErrProfileEndpointInvalid
		}
		if _, found := bindings[b.Name]; found {
			return out, value.ErrProfileEndpointAmbiguous
		}
		if _, found := profiles[b.Name]; found {
			return out, value.ErrProfileEndpointAmbiguous
		}
		bindings[b.Name] = b
	}
	if b, found := bindings[in.SourceRef]; found {
		d, present := templates[b.TemplateRef]
		if !present {
			return out, value.ErrProfileEndpointUnavailable
		}
		if !slices.Contains(d.AddressModes, b.AddressMode) {
			return out, value.ErrProfileEndpointDenied
		}
		var port uint16
		matches := 0
		for _, p := range in.Network.Ports {
			if p.Name == b.PortName {
				matches++
				if p.Protocol == "TCP" {
					port = p.Port
				}
			}
		}
		if matches > 1 {
			return out, value.ErrProfileEndpointAmbiguous
		}
		if matches == 0 || port == 0 {
			return out, value.ErrProfileEndpointUnavailable
		}
		if port < d.MinimumPort || port > d.MaximumPort {
			return out, value.ErrProfileEndpointDenied
		}
		out.Definition, out.SourceKind, out.AddressMode, out.Port, out.DeclaredPortName = d, "templateBinding", b.AddressMode, port, b.PortName
	} else if p, found := profiles[in.SourceRef]; found {
		out.Definition, out.SourceKind, out.AddressMode, out.Port = p.Definition, "administratorProfile", p.AddressMode, p.Port
	} else {
		return out, value.ErrProfileEndpointUnavailable
	}
	// Only the selected applicable definition can expose a dependency/credential
	// denial. Foreign catalog entries are indistinguishable from absent entries.
	if err := profileDefinitionInScope(out.Definition, in); err != nil {
		return value.GoEndpointPlan{}, err
	}
	if credential := out.Definition.Credential; credential != nil {
		matched := false
		for _, audience := range credential.Audiences {
			matched = matched || audience.Matches(in.Network.Target.Request)
		}
		if !matched {
			return value.GoEndpointPlan{}, value.ErrProfileEndpointDenied
		}
	}
	if out.AddressMode == "podIP" {
		if !in.Network.PrimaryIP.IsValid() {
			return value.GoEndpointPlan{}, value.ErrProfileEndpointUnavailable
		}
		out.RouteIP = in.Network.PrimaryIP
	} else if out.Definition.LoopbackFamily == "ipv4" {
		out.RouteIP = netip.MustParseAddr("127.0.0.1")
	} else {
		out.RouteIP = netip.MustParseAddr("::1")
	}
	out.Definition = cloneProfileDefinition(out.Definition)
	out.SourceRef, out.Target, out.Pin = in.SourceRef, in.Network.Target.Request, in.Network.Target.Pin
	out.NodeUID, out.NodeBootID = in.Network.Target.NodeUID, in.Network.Target.NodeBootID
	out.Parameters, out.NativeLimit = in.Parameters, in.NativeLimit
	out.ObservedAt = identity.Earlier(in.Catalog.ObservedAt, in.Network.Target.ObservedAt)
	out.ValidUntil = identity.Earlier(in.Deadline, identity.Earlier(in.Catalog.FreshUntil, in.Network.Target.FreshUntil))
	// Current observations/resource versions are provenance, not immutable
	// endpoint scope. All resolved network and public policy facts are included.
	definition := struct {
		Format     string                     `json:"format"`
		Definition value.GoEndpointDefinition `json:"definition"`
	}{"asservat-go-profile-definition/v1", out.Definition}
	_, definitionDigest, err := profileEndpointCanonical(definition)
	if err != nil {
		return value.GoEndpointPlan{}, value.ErrProfileEndpointInvalid
	}
	out.DefinitionDigest = definitionDigest
	scope := struct {
		Format string               `json:"format"`
		Plan   value.GoEndpointPlan `json:"plan"`
	}{"asservat-go-profile-endpoint/v1", out}
	scope.Plan.ObservedAt, scope.Plan.ValidUntil = time.Time{}, time.Time{}
	_, digest, err := profileEndpointCanonical(scope)
	if err != nil || out.DefinitionDigest == (artifact.Digest{}) || digest == (artifact.Digest{}) {
		return value.GoEndpointPlan{}, value.ErrProfileEndpointInvalid
	}
	out.EndpointDigest = digest
	return out, nil
}

func profileDefinitionApplicable(d value.GoEndpointDefinition, in value.GoEndpointInput) bool {
	r := in.Network.Target.Request
	return d.Source.InCluster(r) && (d.ScopeNamespaceUID == "" || d.ScopeNamespaceUID == r.Namespace.UID)
}

func profileDefinitionInScope(d value.GoEndpointDefinition, in value.GoEndpointInput) error {
	if !d.Valid() {
		return value.ErrProfileEndpointInvalid
	}
	r := in.Network.Target.Request
	if !d.Source.InCluster(r) || (d.ScopeNamespaceUID != "" && d.ScopeNamespaceUID != r.Namespace.UID) || (d.TLS != nil && !d.TLS.Trust.InCluster(r)) || (d.Credential != nil && !d.Credential.Policy.InCluster(r)) {
		return value.ErrProfileEndpointDenied
	}
	return nil
}

func cloneProfileDefinition(d value.GoEndpointDefinition) value.GoEndpointDefinition {
	d.AddressModes = slices.Clone(d.AddressModes)
	slices.Sort(d.AddressModes)
	if d.TLS != nil {
		tls := *d.TLS
		d.TLS = &tls
	}
	if d.Credential != nil {
		credential := *d.Credential
		credential.Audiences = slices.Clone(credential.Audiences)
		slices.SortFunc(credential.Audiences, func(a, b value.GoEndpointAudience) int {
			return cmp.Or(cmp.Compare(a.ClusterID, b.ClusterID), cmp.Compare(a.NamespaceUID, b.NamespaceUID), cmp.Compare(a.WorkloadKind, b.WorkloadKind), cmp.Compare(a.WorkloadUID, b.WorkloadUID))
		})
		d.Credential = &credential
	}
	return d
}

func profileEndpointCanonical(v any) ([]byte, artifact.Digest, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, artifact.Digest{}, err
	}
	return canonical(b)
}
