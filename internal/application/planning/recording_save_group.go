package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/planning"
	"encoding/json"
)

// ReadRecordingSaveChildScopeIdentity joins an independently protected child
// membership to the complete reviewed selection. A group parent has no single
// Pod identity; existing per-child effects must use this exact projection.
func ReadRecordingSaveChildScopeIdentity(raw []byte, digest artifact.Digest, group value.RecordingSaveGroupBinding, childCaptureID string) (ContextScopeIdentity, error) {
	if len(raw) == 0 || len(raw) > 65536 || digest == (artifact.Digest{}) {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	identity, err := readRecordingSaveScopeIdentity(raw, digest)
	if err != nil || group.SelectionDigest != digest || group.ParentCaptureID != identity.CaptureID || !authorization.UUID(childCaptureID) || childCaptureID == group.ParentCaptureID || group.ChildCount < 1 || group.ChildCount > 16 || group.ChildIndex < 0 || group.ChildIndex >= group.ChildCount {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	targets := identity.Targets
	if len(targets) == 0 {
		targets = []authorization.Target{identity.Target}
	}
	if len(targets) != group.ChildCount {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	identity.Target = targets[group.ChildIndex]
	identity.Targets = nil
	identity.CaptureID = childCaptureID
	return identity, nil
}

// Aggregate dependencies preserve source order and independent per-Pod proofs.
// They are historical plan dependencies, never renewed current authority.
func recordingSaveGroupDependencyDigests(sources []recordingSaveScopeSource) (artifact.Digest, artifact.Digest) {
	type entry struct {
		SourceID string `json:"sourceSessionID"`
		Digest   string `json:"digest"`
	}
	ceilings, retentions := make([]entry, len(sources)), make([]entry, len(sources))
	for index, source := range sources {
		ceilings[index] = entry{source.SourceID, source.CeilingDigest}
		retentions[index] = entry{source.SourceID, source.RetentionDigest}
	}
	ceilingRaw, _ := json.Marshal(ceilings)
	retentionRaw, _ := json.Marshal(retentions)
	_, ceiling, _ := canonical(ceilingRaw)
	_, retention, _ := canonical(retentionRaw)
	return ceiling, retention
}
