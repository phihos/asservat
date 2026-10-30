package postgres

import (
	"context"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// The accepted request names a source, but never supplies its binding. Read the
// retained original independently; no replacement source is selected here.
func sourceSnapshotWork(ctx context.Context, q *custodydb.Queries, root string, w *executionapp.APIContextWork) error {
	e := w.Accepted.Expectation
	if e.Snapshot == nil {
		if w.SourceBinding != nil {
			return value.ErrInvalid
		}
		return nil
	}
	row, err := q.ReadPolicyRecordingSource(ctx, custodydb.ReadPolicyRecordingSourceParams{RootID: id(root), ID: id(e.Snapshot.SourceID)})
	if err != nil {
		return err
	}
	source, err := policySourceState(row)
	if err != nil {
		return err
	}
	if err := sourceProvenanceComplete(source); err != nil {
		return err
	}
	b := source.Binding
	if source.Target == nil || !source.Target.Valid() || source.Target.SourceID != b.SourceID || source.Target.Fence != b.Fence || source.Target.BindingDigest != [32]byte(e.Snapshot.SourceBindingDigest) || len(source.Audience) == 0 || b.AudienceDigest == ([32]byte{}) {
		return value.ErrDenied
	}
	_, policy, isPolicy := authorization.PolicyExecutor(w.Actor)
	if !isPolicy || policy != b.PolicyUID || b.RootID != root || source.ClusterID != e.Registration.Location.ClusterID || source.NamespaceUID != e.NamespaceUID || source.WorkloadUID != e.WorkloadUID || b.PodUID != e.PodUID || b.ActionID != e.ActionID || b.Fence != e.Snapshot.Fence || artifact.Digest(deliveryapp.SourceBindingDigest(b)) != e.Snapshot.SourceBindingDigest || !source.StartedAt.Equal(e.Snapshot.SourceStartedAt) || !source.HardUntil.Equal(e.Snapshot.SourceHardUntil) {
		return value.ErrChanged
	}
	if source.Target.Pin != w.Accepted.Pin || source.Target.Target() != (authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}) {
		return value.ErrChanged
	}
	w.Target = source.Target.Request
	w.SourceBinding = &b
	w.SourceAudience = source.Audience
	w.SourceTarget = source.Target
	return nil
}
