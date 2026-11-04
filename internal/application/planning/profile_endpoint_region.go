package planning

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ProfileEndpointEntry is one entry of a region's protected profile endpoint
// configuration (ADR-285): an administrator template (Profile false) that
// maintainers bind to a declared Pod port, or a fully configured
// administrator profile with a fixed address mode and port. Namespaces
// lists the namespace names it applies to; empty applies to every namespace.
// Definition.ScopeNamespaceUID is derived per request from Namespaces.
type ProfileEndpointEntry struct {
	Definition  value.GoEndpointDefinition
	Namespaces  []string
	Profile     bool
	AddressMode string
	Port        uint16
}

// ResolveProfileEndpointRequest answers one preview query in the target's
// region: the protected entries and the exact Pod's routing observation pass
// through the pure endpoint planner. Nothing is dialed, probed or read from
// a credential; the answer carries no address or secret material.
func ResolveProfileEndpointRequest(entries []ProfileEndpointEntry, network targets.ProfileNetwork, r targets.ProfileEndpointRequest, now time.Time) (targets.ProfileEndpointResolution, error) {
	plan, err := ResolveProfileEndpointPlan(entries, network, r, now)
	if err != nil {
		return targets.ProfileEndpointResolution{}, err
	}
	var out targets.ProfileEndpointResolution
	out = targets.ProfileEndpointResolution{Request: r, SourceKind: plan.SourceKind, SourceName: plan.Definition.Source.Name, AddressMode: plan.AddressMode, Port: plan.Port, DeclaredPortName: plan.DeclaredPortName,
		PathPolicy: plan.Definition.PathPolicy, TLS: plan.Definition.TLS != nil, Credential: plan.Definition.Credential != nil, DefinitionDigest: plan.DefinitionDigest, EndpointDigest: plan.EndpointDigest}
	out.Request.Bindings = slices.Clone(r.Bindings)
	if !out.Answers(r) {
		return targets.ProfileEndpointResolution{}, targets.ErrInvalid
	}
	return out, nil
}

// ResolveProfileEndpointPlan retains the private numeric route for an exact admitted acquisition.
func ResolveProfileEndpointPlan(entries []ProfileEndpointEntry, network targets.ProfileNetwork, r targets.ProfileEndpointRequest, now time.Time) (value.GoEndpointPlan, error) {
	var out value.GoEndpointPlan
	if !r.Valid() || !network.Valid(now) || network.Target.Request != r.Target {
		return out, targets.ErrInvalid
	}
	if len(entries) == 0 {
		return out, targets.ErrUnsupported
	}
	until := now.Add(5 * time.Second)
	in := value.GoEndpointInput{SourceRef: r.SourceRef, Network: network, NativeLimit: r.NativeLimit, Deadline: until,
		Parameters: execution.GoProfileParameters{Type: r.Type, Mode: r.Mode, Duration: time.Duration(r.DurationSeconds) * time.Second, ForceGC: r.ForceGC},
		Catalog:    value.GoEndpointCatalog{ObservedAt: now, FreshUntil: until}}
	for _, b := range r.Bindings {
		in.Bindings = append(in.Bindings, value.GoEndpointBinding{Name: b.Name, TemplateRef: b.TemplateRef, AddressMode: b.AddressMode, PortName: b.PortName})
	}
	in.Catalog = profileEndpointCatalog(entries, r.Target.Namespace)
	in.Catalog.ObservedAt, in.Catalog.FreshUntil = now, until
	plan, err := ResolveGoProfileEndpoint(in, now)
	if err != nil {
		return out, profileEndpointTargetError(err)
	}
	return plan, nil
}

func profileEndpointTargetError(err error) error {
	switch {
	case errors.Is(err, value.ErrProfileEndpointAmbiguous):
		return targets.ErrEndpointAmbiguous
	case errors.Is(err, value.ErrProfileEndpointUnavailable):
		return targets.ErrEndpointUnavailable
	case errors.Is(err, value.ErrProfileEndpointDenied):
		return targets.ErrEndpointDenied
	case errors.Is(err, value.ErrProfileHostNetwork):
		return targets.ErrEndpointHostNetwork
	default:
		return targets.ErrInvalid
	}
}

func profileEndpointCatalog(entries []ProfileEndpointEntry, namespace configuration.NamespaceRef) value.GoEndpointCatalog {
	var catalog value.GoEndpointCatalog
	for _, e := range entries {
		if len(e.Namespaces) > 0 && !slices.Contains(e.Namespaces, namespace.Name) {
			continue // not applicable: indistinguishable from absent
		}
		d := cloneProfileDefinition(e.Definition)
		d.ScopeNamespaceUID = ""
		if len(e.Namespaces) > 0 {
			d.ScopeNamespaceUID = namespace.UID
		}
		if e.Profile {
			catalog.Profiles = append(catalog.Profiles, value.GoEndpointProfile{Definition: d, AddressMode: e.AddressMode, Port: e.Port})
		} else {
			catalog.Templates = append(catalog.Templates, d)
		}
	}
	return catalog
}
