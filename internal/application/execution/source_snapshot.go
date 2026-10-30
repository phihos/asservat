package execution

import (
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
	return &planning.SourceSnapshotContext{Request: *e.Snapshot, ActionID: e.ActionID, PolicyUID: b.PolicyUID, TriggerKind: e.Lifecycle.TriggerKind, ExecutionDigest: artifact.Digest(b.Scope), RecipeDigest: e.RecipeDigest, SourceAudience: w.SourceAudience, SourceAudienceDigest: artifact.Digest(b.AudienceDigest), SourceTarget: w.SourceTarget}, nil
}
