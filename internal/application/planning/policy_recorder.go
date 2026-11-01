package planning

import (
	"asservat.local/asservat/internal/domain/collector"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// CompilePolicyRecorder shares profile expansion, typed edits, libpcap program
// validation and action normalization with manual captures. Its result is inert
// configuration, with no manual preview, capture UID or invented target.
func CompilePolicyRecorder(c value.ProfileComposition, filters FilterCompiler) (value.PolicyRecorderConfiguration, error) {
	return compilePolicyRecorder(c, filters, false)
}

// CompileOngoingPolicyRecorder is the private source-purpose compiler. Runtime
// composition must qualify the source/Save path before selecting it publicly.
func CompileOngoingPolicyRecorder(c value.ProfileComposition, filters FilterCompiler) (value.PolicyRecorderConfiguration, error) {
	return compilePolicyRecorder(c, filters, true)
}

func compilePolicyRecorder(c value.ProfileComposition, filters FilterCompiler, sources bool) (value.PolicyRecorderConfiguration, error) {
	var out value.PolicyRecorderConfiguration
	actions, profile, err := expand(c, filters)
	if err != nil {
		return out, err
	}
	if len(actions) != 1 || actions[0].packet == nil && actions[0].syscall == nil {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "policy execution supports one network-header packet or syscall metadata action")
	}
	component := c.Components[0]
	a, summary, filter, err := normalizedRecorderAction(actions[0], component.ID)
	if err != nil {
		return out, err
	}
	if actions[0].packet != nil && summary.PacketProfile != "networkHeaders" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "only network-header recording is available")
	}
	if actions[0].syscall != nil && (summary.SyscallMode != "metadata" || summary.ExecutionMode != "ongoing") {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "syscall policies record metadata from an ongoing source")
	}
	if summary.ExecutionMode != "onTrigger" && summary.ExecutionMode != "ongoing" || summary.ExecutionMode == "onTrigger" && summary.Before != "0s" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "select an ongoing source or an explicit onTrigger recording with before 0s")
	}
	if summary.ExecutionMode == "ongoing" && !sources {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "ongoing source and Save qualification is not enabled")
	}
	if summary.ExecutionMode == "ongoing" && len(actions[0].sensitive) > 0 {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "ongoing sources support ordinary network-header predicates only")
	}
	after, ok := durationValue(summary.After, true)
	if !ok || after > 5*time.Minute || after < time.Second && summary.ExecutionMode != "ongoing" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "a policy incident records between one second and five minutes")
	}
	for n, e := range component.Edits {
		if e.Field == "actionMaxBytes" && e.Number > artifact.RecordingNativeLimit {
			return out, refuse(value.CompositionInvalid, pathf("profile_composition.components[0].overrides[%d].value", n), "a capture can save at most 8 MiB in this release; lower the output limit")
		}
	}
	summary.Sensitive = slices.Clone(actions[0].sensitive)
	expanded := recipeSpec{Description: ExpandedRecipeDescription, Actions: []recipeAction{a}, MaxTotalBytes: c.MaxTotalBytes, MaxDuration: c.MaxDuration}
	recipe, err := json.Marshal(expanded)
	if err != nil {
		return out, value.ErrInvalid
	}
	recipe, recipeDigest, err := canonical(recipe)
	if err != nil {
		return out, value.ErrInvalid
	}
	record := struct {
		Version  string                `json:"schemaVersion"`
		Authored wireComposition       `json:"authored"`
		Profile  wireResolved          `json:"profile"`
		Recipe   json.RawMessage       `json:"recipe"`
		Filter   *compiledFilterRecord `json:"filter,omitempty"`
	}{"policy-recorder/v1", authored(c), profile.wire(component.ID), recipe, filter}
	scope, err := json.Marshal(record)
	if err != nil {
		return out, value.ErrInvalid
	}
	scope, digest, err := canonical(scope)
	if err != nil {
		return out, value.ErrInvalid
	}
	out = value.PolicyRecorderConfiguration{Composition: *c.Clone(), Profile: value.ResolvedProfile{ComponentID: component.ID, Ref: component.Profile, DefinitionDigest: profile.Digest}, Action: summary, Recipe: recipe, RecipeDigest: recipeDigest, Scope: scope, Digest: digest}
	if s := actions[0].syscall; s != nil && s.Syscalls.Mode == "include" {
		out.SyscallInclude = slices.Sorted(slices.Values(s.Syscalls.Names))
	}
	if actions[0].filter != nil {
		f := *actions[0].filter
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
