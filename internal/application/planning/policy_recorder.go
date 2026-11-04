package planning

import (
	"asservat.local/asservat/internal/domain/collector"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// CompilePolicyRecorder shares profile expansion, typed edits, libpcap program
// validation and action normalization with manual captures. Its result is inert
// configuration, with no manual preview, capture UID or invented target.
func CompilePolicyRecorder(c value.ProfileComposition, filters FilterCompiler, endpoints ...*value.PolicyProfileEndpoint) (value.PolicyRecorderConfiguration, error) {
	all, err := compilePolicyRecorders(c, filters, false, endpoints...)
	if err != nil {
		return value.PolicyRecorderConfiguration{}, err
	}
	if len(all) != 1 {
		return value.PolicyRecorderConfiguration{}, refuse(value.CompositionRecorderUnavailable, "profile_composition", "onTrigger policies record one action")
	}
	return all[0], nil
}

// CompileOngoingPolicyRecorder compiles a one-recorder source composition.
func CompileOngoingPolicyRecorder(c value.ProfileComposition, filters FilterCompiler, endpoints ...*value.PolicyProfileEndpoint) (value.PolicyRecorderConfiguration, error) {
	all, err := compilePolicyRecorders(c, filters, true, endpoints...)
	if err != nil {
		return value.PolicyRecorderConfiguration{}, err
	}
	if len(all) != 1 {
		return value.PolicyRecorderConfiguration{}, value.ErrInvalid
	}
	return all[0], nil
}

// CompileOngoingPolicyRecorders is the private source-purpose compiler: one
// configuration per composed recorder action (ADR-275), each a complete
// single-action source sharing the authored composition. Runtime composition
// must qualify the source/Save path before selecting it publicly.
func CompileOngoingPolicyRecorders(c value.ProfileComposition, filters FilterCompiler, endpoints ...*value.PolicyProfileEndpoint) ([]value.PolicyRecorderConfiguration, error) {
	return compilePolicyRecorders(c, filters, true, endpoints...)
}

// PolicyProfileEndpointNeeded asks for the protected definition only. The
// composition root supplies its accepted workload namespace; no Pod is invented.
type PolicyProfileEndpointNeeded struct {
	SourceRef string
	Bindings  []targets.ProfileEndpointBinding
	Path      string
}

func (e PolicyProfileEndpointNeeded) Error() string {
	return "the profile endpoint definition at " + e.Path + " needs the target region's resolution"
}

func compilePolicyRecorders(c value.ProfileComposition, filters FilterCompiler, sources bool, endpoints ...*value.PolicyProfileEndpoint) ([]value.PolicyRecorderConfiguration, error) {
	actions, profiles, err := expand(c, filters, nil)
	if err != nil {
		return nil, err
	}
	if len(endpoints) > 1 || len(endpoints) > 0 && (len(actions) != 1 || actions[0].profile == nil) {
		return nil, value.ErrInvalid
	}
	out := make([]value.PolicyRecorderConfiguration, 0, len(actions))
	for _, x := range actions {
		ci := slices.IndexFunc(c.Components, func(p value.ProfileComponent) bool { return p.ID == x.componentID })
		if x.packet == nil && x.syscall == nil && x.profile == nil || ci < 0 {
			return nil, refuse(value.CompositionRecorderUnavailable, "profile_composition", "policy execution supports network-header packets, ongoing syscall metadata and finite syscall arguments")
		}
		var endpoint *value.PolicyProfileEndpoint
		if x.profile != nil {
			if len(actions) != 1 || x.profile.Runtime != "go" || x.profile.Source.Kind != "httpEndpoint" {
				return nil, refuse(value.CompositionRecorderUnavailable, "profile_composition", "a policy acquires one finite Go endpoint profile")
			}
			request := targets.ProfileEndpointDefinitionRequest{SourceRef: x.profile.Source.ProfileRef, Bindings: profileEndpointBindings(x)}
			if len(endpoints) == 0 {
				return nil, PolicyProfileEndpointNeeded{SourceRef: request.SourceRef, Bindings: request.Bindings, Path: pathf("profile_composition.components[%d] action %s.parameters.source.profileRef", ci, x.localID)}
			}
			endpoint = endpoints[0].Clone()
			if !endpoint.Valid() || endpoint.SourceRef != request.SourceRef {
				return nil, value.ErrInvalid
			}
			digest, digestErr := ProfileEndpointDefinitionDigest(endpoint.Definition)
			if digestErr != nil || digest != endpoint.DefinitionDigest {
				return nil, value.ErrInvalid
			}
			if endpoint.Binding != nil && !slices.Contains(request.Bindings, *endpoint.Binding) {
				return nil, value.ErrInvalid
			}
			if endpoint.Binding == nil && slices.ContainsFunc(request.Bindings, func(b targets.ProfileEndpointBinding) bool { return b.Name == request.SourceRef }) {
				return nil, value.ErrInvalid
			}
		}
		one, err := compilePolicyAction(c, ci, x, profiles[ci], sources, endpoint)
		if err != nil {
			return nil, err
		}
		out = append(out, one)
	}
	return out, nil
}

func compilePolicyAction(c value.ProfileComposition, ci int, x expandedAction, profile resolvedProfile, sources bool, endpoint *value.PolicyProfileEndpoint) (value.PolicyRecorderConfiguration, error) {
	var out value.PolicyRecorderConfiguration
	component := c.Components[ci]
	a, summary, filter, err := normalizedRecorderAction(x, component.ID)
	if err != nil {
		return out, err
	}
	if x.packet != nil && summary.PacketProfile != "networkHeaders" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "only network-header recording is available")
	}
	finiteArguments := x.arguments != nil && summary.SyscallMode == "arguments" && summary.ExecutionMode == "onTrigger"
	finiteProfile := x.profile != nil && endpoint.Valid() && summary.ExecutionMode == "onTrigger"
	if x.syscall != nil && !finiteArguments && (summary.SyscallMode != "metadata" || summary.ExecutionMode != "ongoing") {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "syscall policies require an ongoing metadata source or explicit finite approved arguments")
	}
	if summary.ExecutionMode != "onTrigger" && summary.ExecutionMode != "ongoing" || summary.ExecutionMode == "onTrigger" && summary.Before != "0s" && !finiteProfile {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "select an ongoing source or an explicit onTrigger recording with before 0s")
	}
	if summary.ExecutionMode == "ongoing" && !sources {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "ongoing source and Save qualification is not enabled")
	}
	if summary.ExecutionMode == "ongoing" && len(x.sensitive) > 0 {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "ongoing sources support ordinary network-header predicates only")
	}
	after, ok := durationValue(summary.After, true)
	if !finiteProfile && (!ok || after > 5*time.Minute || after < time.Second && summary.ExecutionMode != "ongoing") {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "a policy incident records between one second and five minutes")
	}
	for n, e := range component.Edits {
		if !finiteProfile && e.Field == "actionMaxBytes" && e.Number > artifact.RecordingNativeLimit {
			return out, refuse(value.CompositionInvalid, pathf("profile_composition.components[%d].overrides[%d].value", ci, n), "a capture can save at most 8 MiB in this release; lower the output limit")
		}
	}
	summary.Sensitive = slices.Clone(x.sensitive)
	expanded := recipeSpec{Description: ExpandedRecipeDescription, Actions: []recipeAction{a}, MaxTotalBytes: c.MaxTotalBytes, MaxDuration: c.MaxDuration}
	if finiteProfile {
		expanded.EndpointBindings = slices.Clone(x.bindings)
	}
	recipe, err := json.Marshal(expanded)
	if err != nil {
		return out, value.ErrInvalid
	}
	recipe, recipeDigest, err := canonical(recipe)
	if err != nil {
		return out, value.ErrInvalid
	}
	var argument *argumentProgramRecord
	if finiteArguments {
		p := argumentRecord(summary.ID, x.syscall.Syscalls.Names, *x.arguments)
		argument = &p
	}
	record := struct {
		Version         string                       `json:"schemaVersion"`
		Authored        wireComposition              `json:"authored"`
		Profile         wireResolved                 `json:"profile"`
		Recipe          json.RawMessage              `json:"recipe"`
		Filter          *compiledFilterRecord        `json:"filter,omitempty"`
		Argument        *argumentProgramRecord       `json:"argumentProgram,omitempty"`
		ProfileEndpoint *value.PolicyProfileEndpoint `json:"profileEndpoint,omitempty"`
	}{"policy-recorder/v1", authored(c), profile.wire(component.ID), recipe, filter, argument, endpoint.Clone()}
	scope, err := json.Marshal(record)
	if err != nil {
		return out, value.ErrInvalid
	}
	scope, digest, err := canonical(scope)
	if err != nil {
		return out, value.ErrInvalid
	}
	out = value.PolicyRecorderConfiguration{Composition: *c.Clone(), Profile: value.ResolvedProfile{ComponentID: component.ID, Ref: component.Profile, DefinitionDigest: profile.Digest}, Action: summary, Recipe: recipe, RecipeDigest: recipeDigest, Scope: scope, Digest: digest}
	if finiteProfile {
		out.ProfileEndpoint = endpoint.Clone()
		out.Profile.SourceClusterID, out.Profile.SourceNamespaceUID, out.Profile.SourceUID, out.Profile.Deprecated = profile.SourceClusterID, profile.SourceNamespaceUID, profile.SourceUID, profile.Deprecated
	}
	if finiteArguments {
		a := *x.arguments
		out.Arguments = &a
	}
	if s := x.syscall; s != nil && s.Syscalls.Mode == "include" {
		out.SyscallInclude = slices.Sorted(slices.Values(s.Syscalls.Names))
	}
	if x.filter != nil {
		f := *x.filter
		f.Program = slices.Clone(f.Program)
		out.Filter = &f
	}
	return out, nil
}

// SyscallSource is the accepted syscall selection a policy source carries
// (ADR-273); its digest is bound into the source's ProgramDigest.
func SyscallSource(p value.PolicyRecorderConfiguration) collector.SyscallFilter {
	return collector.SyscallFilter{Names: slices.Clone(p.SyscallInclude), ErrorsOnly: p.Action.Result == "errors", MaxEvents: p.Action.MaxEvents, MaxTrackedThreads: p.Action.MaxTrackedThreads}
}
