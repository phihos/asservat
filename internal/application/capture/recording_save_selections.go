package capture

import (
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"context"
)

// Each original principal/client-bound set is read once. References keep the
// caller's handle order; sets are neither merged, rewritten nor renewed. The
// first real set supplies only their independently matched workload context.
func (s RecordingSaves) recordingSelectionReferences(ctx context.Context, actor identity.Principal, handles []string) (value.RecordingSelectionSet, []value.RecordingReference, error) {
	var first value.RecordingSelectionSet
	if len(handles) < 1 || len(handles) > value.MaxRecordingSaveGroupChildren {
		return first, nil, value.ErrInvalid
	}
	order := []string{}
	positions := map[string][]int{}
	seenHandles := map[string]bool{}
	for n, h := range handles {
		id, _, ok := value.ParseRecordingHandle(h)
		if !ok || seenHandles[h] {
			return first, nil, value.ErrInvalid
		}
		seenHandles[h] = true
		if _, ok := positions[id]; !ok {
			order = append(order, id)
		}
		positions[id] = append(positions[id], n)
	}
	refs := make([]value.RecordingReference, len(handles))
	sets := make([]value.RecordingSelectionSet, 0, len(order))
	for _, id := range order {
		set, err := s.Inventory.Selections.ReadRecordingSelection(ctx, actor, id)
		if err != nil {
			return first, nil, err
		}
		if !set.Valid() || set.RootID != s.Inventory.RootID || set.Actor != actor {
			return first, nil, value.ErrDenied
		}
		if first.ID == "" {
			first = set.Clone()
		} else if set.Target != first.Target {
			return first, nil, value.ErrInvalid
		}
		subset := make([]string, len(positions[id]))
		for n, pos := range positions[id] {
			subset[n] = handles[pos]
		}
		selected, err := set.Select(actor, subset, s.Inventory.Now())
		if err != nil {
			return first, nil, err
		}
		for n, pos := range positions[id] {
			ref := selected[n]
			if set.PolicyUID != "" && set.PolicyUID != ref.PolicyUID {
				return first, nil, value.ErrChanged
			}
			refs[pos] = ref
		}
		sets = append(sets, set)
	}
	// Later set reads may block. All inputs must still be live when conversion
	// to exact references completes; the protected preview then has its own review.
	now := s.Inventory.Now()
	for _, set := range sets {
		if now.Before(set.CreatedAt) || !now.Before(set.ExpiresAt) {
			return first, nil, value.ErrDenied
		}
	}
	seenSources := map[string]bool{}
	for _, ref := range refs {
		if seenSources[ref.SourceID] || ref.PolicyUID != refs[0].PolicyUID || ref.ExecutionDigest != refs[0].ExecutionDigest {
			return first, nil, value.ErrInvalid
		}
		seenSources[ref.SourceID] = true
	}
	return first, refs, nil
}
