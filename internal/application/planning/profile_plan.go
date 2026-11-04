package planning

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-285: profile actions compile into the recorder-preview/v1 plan. A Go
// endpoint source is resolved by the target's region from its protected
// profile endpoint configuration and frozen into the plan; the eBPF CPU
// sampler names no endpoint. Profile plans are plan-only until a node
// acquires them (S-05 increments 3 and 5).

const (
	// profileMarginMin and profileMarginMax bound the action timeout beyond
	// the timed duration: setup and delivery need at least the recorders'
	// finalization margin, and the Go mechanism refuses an interval longer
	// than duration plus ten seconds (execution.GoProfileRequest).
	profileMarginMin = finalizationMargin
	profileMarginMax = 10 * time.Second
	// maxSamplerDuration bounds an eBPF CPU sampler session (REQ-PRF-002).
	maxSamplerDuration = 60 * time.Second
)

// profileOutputLimit is the registered native bound of a profile action.
func profileOutputLimit(p *profileParameters) int64 {
	if p.Type == "runtimeTrace" {
		return artifact.MaxGoTraceBytes
	}
	return artifact.MaxPprofBytes
}

// profileDuration parses the timed duration; snapshots and cumulative
// counters have none.
func profileDuration(p *profileParameters) (time.Duration, bool) {
	if p.Duration == "" {
		return 0, true
	}
	return durationValue(p.Duration, false)
}

// goProfileShape explains the accepted modes and durations of one Go type.
func goProfileShape(typ string) string {
	switch typ {
	case "cpu":
		return "a Go CPU profile is mode interval for 1 to 60 whole seconds"
	case "runtimeTrace":
		return "a Go execution trace is mode interval for 1 to 15 whole seconds"
	case "heap", "goroutine":
		return "a Go " + typ + " profile is a snapshot without duration, or a delta of 1 to 60 whole seconds"
	}
	return "a Go " + typ + " profile is cumulative without duration, or a delta of 1 to 60 whole seconds"
}

// normalizeProfile validates one profile action (REQ-PRF-001/002): the
// supported sources, Go endpoint type/mode/duration and forced-GC rules,
// the eBPF sampler shape, output and timeout bounds. Live profiling is
// intrusive and always needs an individual approval (ADR-249 liveProfile).
func normalizeProfile(path string, a *expandedAction) error {
	p := a.profile
	if a.action.ExecutionMode == "" {
		a.action.ExecutionMode = "onTrigger" // action.schema.json x-execution-modes
	}
	switch {
	case a.action.ExecutionMode != "onTrigger":
		return refuse(value.CompositionInvalid, path+".executionMode", "a profile runs on trigger: it records only after the request")
	case len(a.action.DependsOn) != 0:
		return refuse(value.CompositionInvalid, path+".dependsOn", "a profile cannot depend on another action")
	case a.action.Impact != "intrusive":
		return refuse(value.CompositionInvalid, path+".impact", "live profiling runs in or samples the application and has impact intrusive")
	case p.FrequencyHz != 0:
		return refuse(value.CompositionRecorderUnavailable, path+".parameters.frequencyHz", "the sampling frequency is not configurable in this release: omit frequencyHz")
	}
	d, ok := profileDuration(p)
	if !ok {
		return refuse(value.CompositionInvalid, path+".parameters.duration", "the duration is a positive duration")
	}
	switch p.Source.Kind {
	case "httpEndpoint":
		if p.Runtime != "go" {
			return refuse(value.CompositionRecorderUnavailable, path+".parameters.runtime", "this release profiles Go pprof endpoints and samples CPU of any runtime with source ebpfSampler; other runtimes need a qualified capability pack")
		}
		if !identity.Text(p.Source.ProfileRef, 63) {
			return refuse(value.CompositionInvalid, path+".parameters.source.profileRef", "name an endpoint binding of this profile or an administrator endpoint profile")
		}
		// REQ-PRF-002: the handler takes its delta path before the GC
		// branch, so forced GC with delta is refused, never ignored.
		if p.ForceGC && p.Mode == "delta" {
			return refuse(value.CompositionInvalid, path+".parameters.forceGC", "forced GC is unavailable with mode delta (the Go handler takes its delta path before the GC branch): use a heap snapshot or set forceGC false")
		}
		if p.ForceGC && (p.Type != "heap" || p.Mode != "snapshot") {
			return refuse(value.CompositionInvalid, path+".parameters.forceGC", "forced GC applies only to a Go heap snapshot")
		}
		switch p.Type {
		case "cpu", "heap", "allocs", "goroutine", "block", "mutex", "threadcreate", "runtimeTrace":
		default:
			return refuse(value.CompositionRecorderUnavailable, path+".parameters.type", "Go endpoints serve cpu, heap, allocs, goroutine, block, mutex, threadcreate and runtimeTrace")
		}
		if !artifact.ValidGoProfile(p.Type, p.Mode, d, p.ForceGC) {
			return refuse(value.CompositionInvalid, path+".parameters.mode", goProfileShape(p.Type))
		}
	case "ebpfSampler":
		if p.Runtime != "any" || p.Type != "cpu" || p.ForceGC || p.Source.ProfileRef != "" {
			return refuse(value.CompositionInvalid, path+".parameters.source", "the eBPF sampler records runtime any, type cpu without forceGC or profileRef")
		}
		if p.Mode != "interval" || d < time.Second || d > maxSamplerDuration || d%time.Second != 0 {
			return refuse(value.CompositionInvalid, path+".parameters.duration", "an eBPF sampler session is mode interval for 1 to 60 whole seconds")
		}
	default:
		return refuse(value.CompositionRecorderUnavailable, path+".parameters.source.kind", "this release profiles through a Go httpEndpoint or the ebpfSampler; other sources need a qualified capability pack")
	}
	timeout, ok := durationValue(a.action.Limits.Timeout, false)
	if !ok || timeout < d+profileMarginMin || timeout > d+profileMarginMax {
		return refuse(value.CompositionInvalid, path+".limits.timeout", fmt.Sprintf("the action timeout is the profile duration (%s) plus 5 to 10 seconds for setup and delivery", d))
	}
	limit := profileOutputLimit(p)
	if a.action.Limits.MaxBytes < 1 || a.action.Limits.MaxBytes > limit {
		return refuse(value.CompositionInvalid, path+".limits.maxBytes", fmt.Sprintf("this profile saves 1 byte to %d MiB", limit>>20))
	}
	a.sensitive = append(a.sensitive, value.ReasonLiveProfile)
	return nil
}

// EndpointResolutionNeeded reports that a plan has a Go endpoint source
// whose region resolution is not in the input. The caller asks the target's
// region for Request and compiles again with the answer; it is never a
// refusal by itself.
type EndpointResolutionNeeded struct {
	Request targets.ProfileEndpointRequest
	Path    string
}

func (e EndpointResolutionNeeded) Error() string {
	return "the profile endpoint at " + e.Path + " needs the target region's resolution"
}

// EndpointResolutionRefusal maps a failed region resolution of needed to
// the composition refusal at its path; any other error is returned
// unchanged. Absent and out-of-scope names are indistinguishable.
func EndpointResolutionRefusal(needed EndpointResolutionNeeded, err error) error {
	switch {
	case errors.Is(err, targets.ErrEndpointUnavailable):
		return refuse(value.CompositionProfileMissing, needed.Path, "no administrator endpoint template, binding or profile of this name applies to the target, or the Pod declares no such TCP port; ask an administrator for an endpoint template")
	case errors.Is(err, targets.ErrEndpointAmbiguous):
		return refuse(value.CompositionEndpointAmbiguous, needed.Path, "the endpoint name or the Pod's port name is declared more than once; use an unambiguous binding or administrator profile")
	case errors.Is(err, targets.ErrEndpointDenied):
		return refuse(value.CompositionEndpointDenied, needed.Path, "the endpoint template does not permit this address mode, port, namespace or workload; ask an administrator to extend the template")
	case errors.Is(err, targets.ErrEndpointHostNetwork):
		return refuse(value.CompositionRecorderUnavailable, needed.Path, "profiling a host-network Pod is not qualified")
	case errors.Is(err, targets.ErrUnsupported):
		return refuse(value.CompositionRecorderUnavailable, needed.Path, "this cluster has no profile endpoint configuration")
	}
	return err
}

// endpointRequest is the region query of one Go endpoint action.
func endpointRequest(t targets.Request, x expandedAction) targets.ProfileEndpointRequest {
	p := x.profile
	d, _ := profileDuration(p)
	r := targets.ProfileEndpointRequest{Target: t, SourceRef: p.Source.ProfileRef, Type: p.Type, Mode: p.Mode, DurationSeconds: int64(d / time.Second), ForceGC: p.ForceGC, NativeLimit: x.action.Limits.MaxBytes}
	r.Bindings = profileEndpointBindings(x)
	return r
}

func profileEndpointBindings(x expandedAction) []targets.ProfileEndpointBinding {
	var bindings []targets.ProfileEndpointBinding
	for _, b := range x.bindings {
		bindings = append(bindings, targets.ProfileEndpointBinding{Name: b.Name, TemplateRef: b.TemplateRef, AddressMode: b.AddressMode, PortName: b.PortName})
	}
	return bindings
}

// resolveEndpoints attaches the frozen region answer to every Go endpoint
// action. A missing answer asks the caller to resolve it; every supplied
// answer must be used exactly once.
func resolveEndpoints(actions []expandedAction, c value.ProfileComposition, t targets.Request, resolved []targets.ProfileEndpointResolution) error {
	used := map[int]bool{}
	for i := range actions {
		x := &actions[i]
		if x.profile == nil || x.profile.Source.Kind != "httpEndpoint" {
			continue
		}
		request := endpointRequest(t, *x)
		found := -1
		for n, r := range resolved {
			if !used[n] && r.Request.Equal(request) {
				found = n
				break
			}
		}
		if found < 0 {
			ci := slices.IndexFunc(c.Components, func(p value.ProfileComponent) bool { return p.ID == x.componentID })
			return EndpointResolutionNeeded{Request: request, Path: pathf("profile_composition.components[%d] action %s.parameters.source.profileRef", ci, x.localID)}
		}
		used[found] = true
		r := resolved[found].Clone()
		if !r.Answers(request) || r.ResolvedAt.IsZero() {
			return value.ErrInvalid
		}
		x.endpoint = &r
	}
	if len(used) != len(resolved) {
		return value.ErrInvalid
	}
	return nil
}

// profileEndpointRecord is the reviewed endpoint of one Go profile action.
type profileEndpointRecord struct {
	ActionID         string `json:"actionID"`
	SourceRef        string `json:"sourceRef"`
	SourceKind       string `json:"sourceKind"`
	SourceName       string `json:"sourceName"`
	AddressMode      string `json:"addressMode"`
	Port             uint16 `json:"port"`
	DeclaredPortName string `json:"declaredPortName,omitempty"`
	PathPolicy       string `json:"pathPolicy"`
	TLS              bool   `json:"tls"`
	Credential       bool   `json:"credential"`
	DefinitionDigest string `json:"definitionDigest"`
	EndpointDigest   string `json:"endpointDigest"`
	ResolvedAt       string `json:"resolvedAt"`
}

func endpointRecord(id string, r targets.ProfileEndpointResolution) profileEndpointRecord {
	return profileEndpointRecord{ActionID: id, SourceRef: r.Request.SourceRef, SourceKind: r.SourceKind, SourceName: r.SourceName, AddressMode: r.AddressMode, Port: r.Port, DeclaredPortName: r.DeclaredPortName, PathPolicy: r.PathPolicy,
		TLS: r.TLS, Credential: r.Credential, DefinitionDigest: hexDigest(r.DefinitionDigest), EndpointDigest: hexDigest(r.EndpointDigest), ResolvedAt: r.ResolvedAt.UTC().Format(time.RFC3339Nano)}
}

// profileSummary fills the review summary of a profile action.
func profileSummary(s *value.RecorderAction, p *profileParameters) {
	s.ProfileRuntime, s.ProfileType, s.ProfileMode, s.ProfileSource, s.Duration, s.ForceGC = p.Runtime, p.Type, p.Mode, p.Source.Kind, p.Duration, p.ForceGC
}
