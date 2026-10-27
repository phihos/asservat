package postgres

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5"
)

// reviewedContextMatches compares immutable review bindings only. Fresh runtime
// observations and the request's new evidence anchor remain independently checked.
func reviewedContextMatches(p value.ContextPreview, a value.Admission) bool {
	in := a.Plan.Input
	r := a.Registration
	return app.ValidContextPreview(p) && p.RootID == a.RootID && p.InstallationID == a.Recovery.InstallationID && p.IssuerEpoch == a.Recovery.IssuerEpoch && p.Actor == in.Executor && p.ExecutionClass == in.Target.ExecutionClass && p.CaptureID == in.CaptureID && p.CaseID == a.CaseID && p.OccurrenceID == a.OccurrenceID && p.ArtifactID == r.Location.ArtifactID && p.AttemptID == r.Location.AttemptID && p.Target == in.Target.Request && p.Pin == in.Target.Pin && p.ScopeDigest == a.Plan.ScopeDigest && bytes.Equal(p.CanonicalScope, a.Plan.CanonicalScope) && p.Deadline.Equal(in.Deadline) && (in.Recorder == nil && p.Intent.Composition == nil && p.AssessmentRulesDigest == planning.ContextAssessmentRulesDigestForClass(p.ExecutionClass) || in.Recorder != nil && p.Intent.Composition != nil && p.AssessmentRulesDigest == planning.RecorderAssessmentRulesDigest()) && p.Storage == (value.ContextStorageSelection{StoreID: r.StoreID, AllocationID: r.AllocationID, PoolRevision: r.PoolRevision, AllocationRevision: r.AllocationRevision, BindingRevision: a.Storage.Revision}) && p.Retention.PurposeRef == in.Retention.PurposeRef && p.Retention.RequestedSeconds == in.Retention.RequestedSeconds && p.Retention.MaximumSeconds == in.Retention.MaximumSeconds && p.Retention.DeletionBudgetSeconds == in.Retention.DeletionBudgetSeconds && slices.Equal(p.Retention.Policies, in.Retention.Policies) && slices.Equal(p.Audience, a.Eligibility.DefaultAudience)
}

func readReviewedContext(ctx context.Context, q *custodydb.Queries, previewID string, a value.Admission) (value.ContextPreview, error) {
	var zero value.ContextPreview
	if err := checkContextPreviewFence(ctx, q, a.RootID, previewID, a.Plan.Input.Executor); err != nil {
		return zero, err
	}
	row, err := q.FindContextPreview(ctx, custodydb.FindContextPreviewParams{RootID: id(a.RootID), ID: id(previewID), ActorKey: previewActorKey(a.Plan.Input.Executor)})
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, value.ErrChanged
	}
	if err != nil {
		return zero, err
	}
	if row.ClosedAt.Valid {
		return zero, value.ErrChanged
	}
	p, err := previewRecord(row)
	if err != nil {
		return zero, err
	}
	if !reviewedContextMatches(p, a) {
		return zero, value.ErrChanged
	}
	if err = currentPreview(ctx, q, p); err != nil {
		return zero, err
	}
	return p, nil
}
