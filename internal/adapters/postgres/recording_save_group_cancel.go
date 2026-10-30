package postgres

import (
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

func (s *APIContextExecutions) requestGroupCancellation(ctx context.Context, q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream, header custodydb.RecordingSaveGroup, in value.CancellationCheck) (app.SnapshotCancellationWork, error) {
	var zero app.SnapshotCancellationWork
	accepted, err := recordingGroupAccepted(ctx, q, header)
	if err != nil {
		return zero, err
	}
	if !header.CancelRequestedAt.Valid && header.ProgressRevision != in.Request.ExpectedRevision {
		return zero, value.ErrConflict
	}
	rows, err := q.ReadRecordingSaveGroupChildren(ctx, custodydb.ReadRecordingSaveGroupChildrenParams{RootID: header.RootID, GroupID: header.ID})
	if err != nil || len(rows) != len(accepted.Group.Children) {
		return zero, value.ErrUnavailable
	}
	work := app.SnapshotCancellationWork{Group: &app.SnapshotCancellationGroup{ParentCaptureID: uid(header.ID)}}
	until := in.ValidUntil
	var observed time.Time
	actions := make([]value.ContextActionProgress, 0, len(rows))
	requested := header.CancelRequestedAt.Valid
	for _, row := range rows {
		child := in
		child.Request.CaptureID = uid(row.ID)
		child.Request.ExpectedRevision = row.ProgressRevision
		child.Request.IdempotencyKey = "group-cancel-" + hex.EncodeToString(contextRequestKey(in.Identity.Principal, in.Request.IdempotencyKey))
		result, err := s.requestSnapshotCancellationInTransaction(ctx, q, trust, stream, child)
		if err != nil {
			return zero, err // no sibling request becomes visible until commit
		}
		requested = requested || result.Decision.Requested
		until = identity.Earlier(until, result.Decision.ValidUntil)
		if observed.IsZero() {
			observed = result.Decision.ObservedAt
		}
		if result.Snapshot != nil {
			work.Group.Targets = append(work.Group.Targets, app.SnapshotCancellationTarget{ClusterID: result.ClusterID, Snapshot: *result.Snapshot})
		}
		actions = append(actions, value.ContextActionProgress{Phase: result.Decision.Phase})
	}
	// Child progress triggers may have advanced the parent revision; retain that
	// exact value rather than summing child revisions or resetting a counter.
	header, err = q.LockRecordingSaveGroup(ctx, custodydb.LockRecordingSaveGroupParams{RootID: header.RootID, ID: header.ID})
	if err != nil {
		return zero, err
	}
	if requested && !header.CancelRequestedAt.Valid {
		header, err = q.RequestRecordingSaveGroupCancellation(ctx, custodydb.RequestRecordingSaveGroupCancellationParams{RootID: header.RootID, ID: header.ID, CancelRequestKey: contextRequestKey(in.Identity.Principal, in.Request.IdempotencyKey), ProgressRevision: header.ProgressRevision})
		if err != nil {
			return zero, err
		}
	}
	phase, _ := recordingGroupPhase(actions)
	work.Decision = value.Cancellation{CaptureID: uid(header.ID), Phase: phase, Revision: header.ProgressRevision, Requested: header.CancelRequestedAt.Valid, ObservedAt: observed, ValidUntil: until}
	if err := s.guards.Recovery.check(ctx, q, trust, s.root, in.Recovery); err != nil {
		return zero, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil || !in.Valid(now.Time) || !work.Decision.Valid(now.Time) {
		return zero, value.ErrDenied
	}
	return work, ctx.Err()
}
