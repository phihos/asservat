package execution

import (
	compiler "asservat.local/asservat/internal/application/planning"
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/planning"
)

func snapshotContext(w APIContextWork) (*planning.SourceSnapshotContext, error) {
	e, b := w.Accepted.Expectation, w.SourceBinding
	if e.Snapshot == nil {
		if b != nil {
			return nil, value.ErrInvalid
		}
		return nil, nil
	}
	if b == nil || !b.Valid() || e.Lifecycle == nil || e.Recording != nil || b.SourceID != e.Snapshot.SourceID || b.Fence != e.Snapshot.Fence || b.ActionID != e.ActionID || b.PodUID != e.PodUID {
		return nil, value.ErrInvalid
	}
	raw, err := json.Marshal(b)
	if err != nil || artifact.Digest(sha256.Sum256(raw)) != e.Snapshot.SourceBindingDigest {
		return nil, value.ErrConflict
	}
	if origin := e.Lifecycle.Origin; origin != nil && (origin.PolicyUID != b.PolicyUID || origin.PolicyExecutionDigest != artifact.Digest(b.Scope)) {
		return nil, value.ErrConflict
	}
	var manualScope []byte
	var definitionDigest artifact.Digest
	if e.Lifecycle.TriggerKind == "recordingSave" && e.SourceSnapshotManifest != nil {
		definitionDigest = artifact.Digest(b.ExpectationDigest)
		manualScope = append([]byte(nil), e.SourceSnapshotManifest.CanonicalScope...)
	}
	group, err := snapshotGroup(w, manualScope)
	if err != nil {
		return nil, err
	}
	return &planning.SourceSnapshotContext{Group: group, RecordingSaveScope: manualScope, SourceDefinitionDigest: definitionDigest, Request: *e.Snapshot, ActionID: e.ActionID, PolicyUID: b.PolicyUID, TriggerKind: e.Lifecycle.TriggerKind, ExecutionDigest: artifact.Digest(b.Scope), RecipeDigest: e.RecipeDigest, SourceAudience: w.SourceAudience, SourceAudienceDigest: artifact.Digest(b.AudienceDigest), SourceTarget: w.SourceTarget}, nil
}

// SQL's accepted-work reader already checks immutable group membership against
// the full scope. Reconstruct its planning view from that same canonical scope
// and exact retained source; no extra authority, query or signed field is added.
func snapshotGroup(w APIContextWork, raw []byte) (*planning.RecordingSaveGroupBinding, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	e := w.Accepted.Expectation
	identity, err := compiler.ReadContextScopeIdentity(raw, e.PlanDigest)
	if err != nil {
		return nil, value.ErrInvalid
	}
	if len(identity.Targets) == 0 {
		return nil, nil
	}
	var scope struct {
		Sources []struct {
			SourceID string `json:"sourceSessionID"`
		} `json:"sources"`
	}
	if json.Unmarshal(raw, &scope) != nil || len(scope.Sources) != len(identity.Targets) || w.SourceTarget == nil {
		return nil, value.ErrInvalid
	}
	for index, source := range scope.Sources {
		if source.SourceID != e.Snapshot.SourceID {
			continue
		}
		group := &planning.RecordingSaveGroupBinding{ParentCaptureID: identity.CaptureID, SelectionDigest: e.PlanDigest, ChildIndex: index, ChildCount: len(scope.Sources)}
		child, err := compiler.ReadRecordingSaveChildScopeIdentity(raw, e.PlanDigest, *group, e.CaptureUID)
		if err != nil || child.Target != w.SourceTarget.Target() || child.Actor != w.Actor {
			return nil, value.ErrConflict
		}
		return group, nil
	}
	return nil, value.ErrConflict
}
