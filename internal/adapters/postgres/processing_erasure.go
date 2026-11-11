package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
)

// Prepare the unchanged lifecycle wire record before audit. The SQL guard
// independently checks these exact retained facts under the custody locks.
func prepareProcessingErasure(ctx context.Context, q *custodydb.Queries, draft app.ProcessingDecision) ([]byte, error) {
	loc := draft.Change.Scope.Location
	a, err := q.ReadAttempt(ctx, id(loc.AttemptID))
	if err != nil || a.ArtifactID != id(loc.ArtifactID) || a.ClusterID != id(loc.ClusterID) || a.State != artifact.StoredUnpublished {
		return nil, value.ErrUnavailable
	}
	c, err := q.ReadRetainedContext(ctx, custodydb.ReadRetainedContextParams{RootID: id(draft.Intent.RootID), AttemptID: a.ID})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	r, err := retainedContextOrigins(ctx, q, draft.Intent.RootID, c, a)
	if err != nil || r.Registration.Location != loc {
		return nil, value.ErrUnavailable
	}
	previous := value.Deadlines{AnchorAt: r.Effective.AnchorAt.UTC(), ExpiresAt: r.Effective.ExpiresAt.UTC(), DeleteBy: r.Effective.DeleteBy.UTC()}
	effective := previous
	effective.ExpiresAt = previous.AnchorAt
	d := value.LifecycleDecision{
		ID: draft.Change.RequestID, RootID: r.RootID, Location: loc, Target: r.Input.Target, Sequence: r.Sequence + 1,
		RegistrationDigest: app.RegistrationDigest(r.Registration), PolicyRevision: value.ErasureLifecycleSource(draft.Change.RequestID, draft.DecisionDigest),
		Policies: slices.Clone(r.OriginPolicies), Origins: slices.Clone(r.OriginPolicies), Previous: previous, Effective: effective,
		ObservedAt: draft.Intent.CreatedAt.UTC(), ValidUntil: draft.Intent.RequestUntil.UTC(),
	}
	if !d.Valid() {
		return nil, value.ErrUnavailable
	}
	return json.Marshal(d)
}

// Replay reports only the existing exact decision and its irreversible cutoff.
// Later policy decisions can advance the sequence and shorten deletion dates.
func verifyProcessingErasure(ctx context.Context, q *custodydb.Queries, row custodydb.ProcessingDecision) error {
	stored, err := q.ReadRetentionDecision(ctx, custodydb.ReadRetentionDecisionParams{ID: row.ID, RootID: row.RootID})
	if err != nil || !bytes.Equal(stored.DecisionJson, row.ErasureDecision) {
		return value.ErrUnavailable
	}
	d, err := decodeLifecycle(stored)
	if err != nil {
		return value.ErrUnavailable
	}
	var prepared artifact.Digest
	copy(prepared[:], row.DecisionDigest)
	if len(row.DecisionDigest) != len(prepared) || d.PolicyRevision != value.ErasureLifecycleSource(uid(row.ID), prepared) {
		return value.ErrUnavailable
	}
	a, err := q.ReadAttempt(ctx, id(d.Location.AttemptID))
	if err != nil || a.ArtifactID != id(d.Location.ArtifactID) || a.ClusterID != id(d.Location.ClusterID) ||
		a.RetentionSequence < d.Sequence || !a.EffectiveExpiresAt.Time.Equal(d.Effective.ExpiresAt) || a.EffectiveDeleteBy.Time.After(d.Effective.DeleteBy) {
		return value.ErrUnavailable
	}
	return nil
}
