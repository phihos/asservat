package planning

import (
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
	var out value.PolicyRecorderConfiguration
	actions, profile, err := expand(c, filters)
	if err != nil {
		return out, err
	}
	if len(actions) != 1 || actions[0].packet == nil {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "policy execution currently supports one network-header packet action")
	}
	component := c.Components[0]
	a, summary, filter, err := normalizedRecorderAction(actions[0], component.ID)
	if err != nil {
		return out, err
	}
	if summary.PacketProfile != "networkHeaders" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "only network-header recording is available")
	}
	if summary.ExecutionMode != "onTrigger" || summary.Before != "0s" {
		return out, refuse(value.CompositionRecorderUnavailable, "profile_composition", "an explicit onTrigger recording with before 0s is required; ongoing policy source arming is not implemented yet")
	}
	after, ok := durationValue(summary.After, true)
	if !ok || after < time.Second || after > 5*time.Minute {
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
	}{"policy-recorder/v1", authored(c), wireResolved{component.ID, wireRef{component.Profile.Catalog, component.Profile.Name, component.Profile.Version}, hexDigest(profile.Digest)}, recipe, filter}
	scope, err := json.Marshal(record)
	if err != nil {
		return out, value.ErrInvalid
	}
	scope, digest, err := canonical(scope)
	if err != nil {
		return out, value.ErrInvalid
	}
	out = value.PolicyRecorderConfiguration{Composition: *c.Clone(), Profile: value.ResolvedProfile{ComponentID: component.ID, Ref: component.Profile, DefinitionDigest: profile.Digest}, Action: summary, Recipe: recipe, RecipeDigest: recipeDigest, Scope: scope, Digest: digest}
	if actions[0].filter != nil {
		f := *actions[0].filter
		f.Program = slices.Clone(f.Program)
		out.Filter = &f
	}
	return out, nil
}
