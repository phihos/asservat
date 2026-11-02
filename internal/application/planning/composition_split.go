package planning

import (
	value "asservat.local/asservat/internal/domain/planning"
)

// SplitComposition splits a manual mixed composition into one child
// composition per component (ADR-276), each compiled exactly like a single
// manual recording. The whole composition is validated first (IDs, aggregate
// bounds, conflicts); a component with more than one action is refused, so
// each child is one recording. A one-component composition is returned as is.
func SplitComposition(c value.ProfileComposition, compiler FilterCompiler) ([]value.ProfileComposition, error) {
	actions, _, err := expand(c, compiler, nil)
	if err != nil {
		return nil, err
	}
	if len(c.Components) == 1 {
		return []value.ProfileComposition{*c.Clone()}, nil
	}
	if len(actions) != len(c.Components) {
		return nil, refuse(value.CompositionRecorderUnavailable, "profile_composition.components", "a manual composition records one action per profile; use a policy for profiles with several actions")
	}
	out := make([]value.ProfileComposition, 0, len(c.Components))
	for i, component := range c.Components {
		child := value.ProfileComposition{Components: []value.ProfileComponent{component}, MaxTotalBytes: c.MaxTotalBytes, MaxDuration: c.MaxDuration}
		for _, r := range c.Resolved {
			if r.Ref == component.Profile {
				child.Resolved = append(child.Resolved, r)
			}
		}
		if !child.Valid() {
			return nil, refuse(value.CompositionInvalid, pathf("profile_composition.components[%d]", i), "the component cannot be recorded on its own")
		}
		out = append(out, *child.Clone())
	}
	return out, nil
}
