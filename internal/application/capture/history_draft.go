package capture

import (
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// HistoryDraftFromPreview copies original authored inputs and immutable version
// pins while the accepted plan is still in memory. It never reconstructs
// recorder settings from incidental plaintext SQL scope_json.
func HistoryDraftFromPreview(p value.ContextPreview, a value.Accepted) (value.HistoryParameters, error) {
	var out value.HistoryParameters
	if p.Group != nil {
		return recordingSaveGroupHistoryDraft(p, a)
	}
	if !p.Valid() || a.CaptureID != p.CaptureID || a.ScopeDigest != p.ScopeDigest || a.Expectation.Validate() != nil {
		return out, value.ErrInvalid
	}
	out = value.HistoryParameters{Format: value.HistoryParametersFormat, Target: p.Intent.Target, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, Diagnostic: p.Intent.Diagnostic, Composition: p.Intent.Composition.Clone(), RequestedSeconds: p.Intent.RequestedSeconds, OriginalEffectiveSeconds: int64(a.Expectation.Registration.ExpiresAt.Sub(a.Expectation.Registration.AnchorAt).Seconds()), OriginalExecutionDigest: a.ScopeDigest}
	if p.Intent.Target.Kind == "Pod" {
		out.ExplicitPodUID = p.Target.PodUID
	}
	if saved := p.Intent.Snapshot; saved != nil && saved.TriggerKind == "recordingSave" {
		out.RecordingSave = &value.RecordingSaveSettings{PolicyUID: saved.PolicyUID, PolicyExecutionDigest: saved.ExecutionDigest, Windows: []value.RecordingSavePreference{{ActionID: saved.ActionID, Before: saved.Request.Before}}}
		out.Selection = "recordingSelectionRequired"
		out.SelectorIdentity = &value.HistorySelector{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadKind: p.Target.Workload.Kind, WorkloadUID: p.Target.Workload.UID}
		api := "apps/v1"
		if p.Intent.Target.Kind == "Pod" {
			api = "v1"
		}
		out.AuthoredTargetJSON, _ = json.Marshal(map[string]any{"namespace": p.Intent.Target.Namespace, "workloadRef": map[string]string{"apiVersion": api, "kind": p.Intent.Target.Kind, "name": p.Intent.Target.Name, "uid": p.Target.Workload.UID}, "maxPods": 1, "selection": "allWithinLimit", "adoption": "pinUID"})
		encoded, err := value.CanonicalHistoryParameters(out)
		clear(encoded)
		if err != nil {
			return value.HistoryParameters{}, err
		}
		return out, nil
	}
	var scope struct {
		Filters    json.RawMessage `json:"filters"`
		Collection struct {
			Spec struct {
				Target json.RawMessage `json:"target"`
			} `json:"spec"`
		} `json:"collection"`
		Recipe       json.RawMessage `json:"recipe"`
		Profiles     json.RawMessage `json:"profileComposition"`
		Dependencies []struct {
			Role   string `json:"role"`
			Digest string `json:"digest"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(p.CanonicalScope, &scope) != nil {
		return value.HistoryParameters{}, value.ErrInvalid
	}
	if p.Intent.Composition != nil {
		out.RecipeJSON = bytes.Clone(scope.Recipe)
		out.CompositionJSON = bytes.Clone(scope.Profiles)
		out.FrozenFilters = bytes.Clone(scope.Filters)
		var pins struct {
			Resolved json.RawMessage `json:"resolvedProfiles"`
			Actions  json.RawMessage `json:"actionMap"`
		}
		if json.Unmarshal(scope.Profiles, &pins) != nil || !json.Valid(pins.Resolved) || !json.Valid(pins.Actions) {
			return value.HistoryParameters{}, value.ErrInvalid
		}
		var resolved []struct {
			DefinitionDigest string `json:"definitionDigest"`
		}
		if json.Unmarshal(pins.Resolved, &resolved) != nil {
			return value.HistoryParameters{}, value.ErrInvalid
		}
		dependencies := []map[string]string{{"role": "recipe", "digest": fmt.Sprintf("%x", a.Expectation.RecipeDigest)}, {"role": "collector", "digest": fmt.Sprintf("%x", a.Expectation.CollectorImageDigest)}}
		for _, pin := range resolved {
			dependencies = append(dependencies, map[string]string{"role": "captureProfile", "digest": pin.DefinitionDigest})
		}
		out.DependencyJSON, _ = json.Marshal(dependencies)
	} else {
		out.RecipeJSON = json.RawMessage(compiler.ContextRecipeSpec)
		pins := scope.Dependencies[:0]
		for _, pin := range scope.Dependencies {
			if pin.Role == "collector" || pin.Role == "projection" || pin.Role == "recipe" {
				pins = append(pins, pin)
			}
		}
		out.DependencyJSON, _ = json.Marshal(pins)
	}
	if p.Intent.Target.Kind == "Pod" {
		out.AuthoredTargetJSON, _ = json.Marshal(map[string]any{"namespace": p.Intent.Target.Namespace, "workloadRef": map[string]string{"apiVersion": "v1", "kind": "Pod", "name": p.Intent.Target.Name, "uid": p.Target.PodUID}, "maxPods": 1, "selection": "allWithinLimit", "adoption": "pinUID"})
	} else if p.Intent.Composition == nil {
		out.AuthoredTargetJSON = bytes.Clone(scope.Collection.Spec.Target)
	} else {
		api := "apps/v1"
		if p.Intent.Target.Kind == "Pod" {
			api = "v1"
		}
		out.AuthoredTargetJSON, _ = json.Marshal(map[string]any{"namespace": p.Intent.Target.Namespace, "workloadRef": map[string]string{"apiVersion": api, "kind": p.Intent.Target.Kind, "name": p.Intent.Target.Name, "uid": p.Target.Workload.UID}, "maxPods": 1, "selection": "allWithinLimit", "adoption": "pinUID"})
	}
	if authored := p.Intent.HistoryAuthored; authored != nil {
		if !authored.Valid() || authored.Selector.NamespaceUID != p.Target.Namespace.UID || authored.Selector.WorkloadUID != p.Target.Workload.UID {
			return value.HistoryParameters{}, value.ErrInvalid
		}
		out.Target = authored.Target
		if authored.Target.Kind != "Pod" {
			out.ExplicitPodUID = ""
		}
		out.AuthoredTargetJSON = bytes.Clone(authored.TargetJSON)
		selector := authored.Selector
		out.SelectorIdentity = &selector
		out.Selection = authored.Selection
		out.PolicyOrigins = append([]value.HistoryPolicyOrigin(nil), authored.PolicyOrigins...)
	}
	b, err := value.CanonicalHistoryParameters(out)
	clear(b)
	if err != nil {
		return value.HistoryParameters{}, err
	}
	return out, nil
}

func recordingSaveGroupHistoryDraft(p value.ContextPreview, a value.Accepted) (value.HistoryParameters, error) {
	if !ValidContextPreview(p) || a.Group == nil || !acceptedContext(a, a.SubmissionDigest) || a.CaptureID != p.CaptureID || a.ScopeDigest != p.ScopeDigest || len(a.Group.Children) != len(p.Group.Children) {
		return value.HistoryParameters{}, value.ErrInvalid
	}
	windows := map[string]time.Duration{}
	requested, effective := int64(0), int64(0)
	for n, c := range p.Group.Children {
		child := a.Group.Children[n]
		if child.CaptureID != c.CaptureID {
			return value.HistoryParameters{}, value.ErrInvalid
		}
		if previous, ok := windows[c.Reference.ActionID]; ok && previous != c.Request.Before {
			return value.HistoryParameters{}, value.ErrSettingsUnavailable
		}
		windows[c.Reference.ActionID] = c.Request.Before
		if requested == 0 || c.Retention.RequestedSeconds < requested {
			requested = c.Retention.RequestedSeconds
		}
		seconds := int64(child.Expectation.Registration.ExpiresAt.Sub(child.Expectation.Registration.AnchorAt).Seconds())
		if effective == 0 || seconds < effective {
			effective = seconds
		}
	}
	prefs := make([]value.RecordingSavePreference, 0, len(windows))
	for action, before := range windows {
		prefs = append(prefs, value.RecordingSavePreference{ActionID: action, Before: before})
	}
	slices.SortFunc(prefs, func(a, b value.RecordingSavePreference) int {
		if a.ActionID < b.ActionID {
			return -1
		}
		if a.ActionID > b.ActionID {
			return 1
		}
		return 0
	})
	out := value.HistoryParameters{Format: value.HistoryParametersFormat, Target: p.Intent.Target, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, RequestedSeconds: requested, OriginalEffectiveSeconds: effective, OriginalExecutionDigest: a.ScopeDigest, Selection: "recordingSelectionRequired", SelectorIdentity: &value.HistorySelector{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadKind: p.Target.Workload.Kind, WorkloadUID: p.Target.Workload.UID}, RecordingSave: &value.RecordingSaveSettings{PolicyUID: p.Group.PolicyUID, PolicyExecutionDigest: p.Group.ExecutionDigest, Windows: prefs}}
	out.AuthoredTargetJSON, _ = json.Marshal(map[string]any{"namespace": p.Intent.Target.Namespace, "workloadRef": map[string]string{"apiVersion": "apps/v1", "kind": p.Intent.Target.Kind, "name": p.Intent.Target.Name, "uid": p.Target.Workload.UID}, "maxPods": len(p.Group.Children), "selection": "allWithinLimit", "adoption": "pinUID"})
	raw, err := value.CanonicalHistoryParameters(out)
	clear(raw)
	return out, err
}
