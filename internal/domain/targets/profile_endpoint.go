package targets

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// Go profile endpoint resolution at preview (ADR-285). The target's region
// resolves one profile action's named source against its protected profile
// endpoint configuration and the exact Pod's routing declarations, without
// dialing, probing or reading a credential. The answer is an observation for
// review that the hub freezes into the plan; it grants nothing.

const (
	// MaxProfileEndpointBindings is the recipe endpointBindings bound.
	MaxProfileEndpointBindings = 16
	// ProfileEndpointTemplateBinding and ProfileEndpointAdministratorProfile
	// are the two source kinds of a resolution.
	ProfileEndpointTemplateBinding      = "templateBinding"
	ProfileEndpointAdministratorProfile = "administratorProfile"
)

var (
	// ErrEndpointUnavailable: no applicable template, binding, profile or
	// declared port; absent and out-of-scope names are indistinguishable.
	ErrEndpointUnavailable = errors.New("profile endpoint unavailable")
	// ErrEndpointAmbiguous: duplicate applicable names or port declarations.
	ErrEndpointAmbiguous = errors.New("profile endpoint ambiguous")
	// ErrEndpointDenied: the selected definition does not permit the address
	// mode, port, namespace or credential audience.
	ErrEndpointDenied = errors.New("profile endpoint outside configured scope")
	// ErrEndpointHostNetwork: host-network Pods need separate qualification.
	ErrEndpointHostNetwork = errors.New("profile endpoint on a host-network pod")
)

// ProfileEndpointBinding is one expanded EvidenceRecipe endpointBindings
// entry: no URL, host, numeric port, path, header or credential.
type ProfileEndpointBinding struct {
	Name, TemplateRef, AddressMode, PortName string
}

func (b ProfileEndpointBinding) Valid() bool {
	return identity.Text(b.Name, 63) && identity.Text(b.TemplateRef, 63) && (b.AddressMode == "targetLoopback" || b.AddressMode == "podIP") && ProfilePortName(b.PortName)
}

// ProfileEndpointRequest asks the target's region to resolve SourceRef for
// one Go profile action on the exact Pod of Target.
type ProfileEndpointRequest struct {
	Target          Request
	SourceRef       string
	Bindings        []ProfileEndpointBinding `json:",omitempty"`
	Type, Mode      string
	DurationSeconds int64
	ForceGC         bool
	NativeLimit     int64
}

func (r ProfileEndpointRequest) Valid() bool {
	if !r.Target.Valid() || !identity.Text(r.SourceRef, 63) || len(r.Bindings) > MaxProfileEndpointBindings || r.DurationSeconds < 0 || r.DurationSeconds > 60 || r.NativeLimit < 1 {
		return false
	}
	if !artifact.ValidGoProfile(r.Type, r.Mode, time.Duration(r.DurationSeconds)*time.Second, r.ForceGC) {
		return false
	}
	limit := artifact.MaxPprofBytes
	if r.Type == "runtimeTrace" {
		limit = artifact.MaxGoTraceBytes
	}
	if r.NativeLimit > limit {
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

// Equal reports whether two requests ask exactly the same query.
func (r ProfileEndpointRequest) Equal(o ProfileEndpointRequest) bool {
	return r.Target == o.Target && r.SourceRef == o.SourceRef && r.Type == o.Type && r.Mode == o.Mode && r.DurationSeconds == o.DurationSeconds && r.ForceGC == o.ForceGC && r.NativeLimit == o.NativeLimit && slices.Equal(r.Bindings, o.Bindings)
}

// ProfileEndpointResolution is the region's public answer to Request. It
// names the selected definition and route, never an address, credential or
// TLS material. ResolvedAt is set by the hub on receipt.
type ProfileEndpointResolution struct {
	Request ProfileEndpointRequest
	// SourceKind is templateBinding or administratorProfile; SourceName is
	// the template's or the administrator profile's name.
	SourceKind, SourceName string
	AddressMode            string
	Port                   uint16
	// DeclaredPortName is the Pod port declaration of a template binding.
	DeclaredPortName string `json:",omitempty"`
	PathPolicy       string
	// TLS and Credential report whether the definition pins TLS trust or a
	// credential reference; neither carries material.
	TLS, Credential                  bool `json:",omitempty"`
	DefinitionDigest, EndpointDigest artifact.Digest
	ResolvedAt                       time.Time `json:",omitzero"`
}

// Clone deep-copies a.
func (a ProfileEndpointResolution) Clone() ProfileEndpointResolution {
	a.Request.Bindings = slices.Clone(a.Request.Bindings)
	return a
}

// Answers reports whether a is a well-formed answer to exactly r.
func (a ProfileEndpointResolution) Answers(r ProfileEndpointRequest) bool {
	if !r.Valid() || !a.Request.Equal(r) || !identity.Text(a.SourceName, 63) || a.Port == 0 || a.PathPolicy != "go-pprof/v1" || a.DefinitionDigest == (artifact.Digest{}) || a.EndpointDigest == (artifact.Digest{}) || (a.AddressMode != "targetLoopback" && a.AddressMode != "podIP") || a.Credential && !a.TLS {
		return false
	}
	switch a.SourceKind {
	case ProfileEndpointTemplateBinding:
		return ProfilePortName(a.DeclaredPortName)
	case ProfileEndpointAdministratorProfile:
		return a.DeclaredPortName == ""
	}
	return false
}
