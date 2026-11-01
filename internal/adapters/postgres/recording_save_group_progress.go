package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// Aggregate only control observations. This never turns a successful sibling
// into permission to read another artifact or erases an uncertain child.
func recordingGroupPhase(actions []value.ContextActionProgress) (string, string) {
	counts := map[string]int{}
	for _, action := range actions {
		counts[action.Phase]++
	}
	if counts["Running"] > 0 {
		return "Running", "GroupInProgress"
	}
	if counts["Pending"] > 0 {
		return "Pending", "GroupPending"
	}
	if counts["Finalizing"] > 0 {
		return "Finalizing", "GroupFinalizing"
	}
	if counts["AwaitingApproval"] > 0 {
		return "AwaitingApproval", "GroupAwaitingApproval"
	}
	if len(actions) > 0 && counts["Succeeded"] == len(actions) {
		return "Succeeded", "Published"
	}
	if counts["Succeeded"]+counts["Partial"] > 0 {
		return "Partial", "GroupPartial"
	}
	if counts["Indeterminate"] > 0 {
		return "Indeterminate", "GroupOutcomeUnconfirmed"
	}
	if len(actions) > 0 && counts["Cancelled"] == len(actions) {
		return "Cancelled", "CancellationJoined"
	}
	return "Failed", "GroupNoEvidence"
}

func (s *ContextProgressReads) readRecordingGroupProgress(ctx context.Context, q *custodydb.Queries, header custodydb.RecordingSaveGroup, request value.ProgressQuery, recovery custodydb.FleetCurrentTrust, stream custodydb.PermissionStream, observedAt time.Time) (value.ContextProgressObservation, error) {
	var zero value.ContextProgressObservation
	accepted, err := recordingGroupAccepted(ctx, q, header)
	if err != nil {
		return zero, err
	}
	rows, err := q.ReadRecordingSaveGroupChildren(ctx, custodydb.ReadRecordingSaveGroupChildrenParams{RootID: header.RootID, GroupID: header.ID})
	if err != nil || len(rows) != len(accepted.Group.Children) {
		return zero, value.ErrUnavailable
	}
	out := value.ContextProgressObservation{CaptureID: uid(header.ID), CandidateCaseID: accepted.Group.CaseID, Operation: "recordingSave", Revision: header.ProgressRevision, CreatedAt: header.AcceptedAt.Time.UTC(), Deadline: header.Deadline.Time.UTC(), ObservedAt: observedAt, ValidUntil: identity.Earlier(observedAt.Add(5*time.Second), request.Recovery.FreshUntil), CancellationRequested: header.CancelRequestedAt.Valid, HistoryState: "unavailable"}
	for n, row := range rows {
		childRequest := request
		childRequest.CaptureID = uid(row.ID)
		child, err := s.readContextProgressInTransaction(ctx, q, row, childRequest, recovery, stream, observedAt)
		if err != nil {
			return zero, err
		}
		if n == 0 {
			out.ReasonMetadata = child.ReasonMetadata
		} else if (out.ReasonMetadata == nil) != (child.ReasonMetadata == nil) || out.ReasonMetadata != nil && (child.ReasonMetadata.Reference != out.ReasonMetadata.Reference || child.ReasonMetadata.CaptureID != out.ReasonMetadata.CaptureID || child.ReasonMetadata.Requester != out.ReasonMetadata.Requester || child.ReasonMetadata.ScopeDigest != out.ReasonMetadata.ScopeDigest) {
			return zero, value.ErrUnavailable
		}
		if n == 0 {
			out.Target = child.Target
			out.Target.PodUID = ""
		}
		out.ValidUntil = identity.Earlier(out.ValidUntil, child.ValidUntil)
		out.CanCancel = out.CanCancel || child.CanCancel
		if row.RepeatedFromCaptureID.Valid && observedAt.Before(row.RepeatedFromExpiresAt.Time) {
			if n == 0 {
				out.RepeatedFrom = child.RepeatedFrom
			} else if out.RepeatedFrom != nil && (child.RepeatedFrom == nil || *out.RepeatedFrom != *child.RepeatedFrom) {
				out.RepeatedFrom = nil
			}
		}
		out.Actions = append(out.Actions, value.ContextActionProgress{InstanceID: uid(row.ID), PodUID: child.Target.PodUID, PodName: accepted.Group.Children[n].Pin.Name, ActionID: child.ActionID, Phase: child.ActionPhase, ReasonCode: child.ReasonCode})
	}
	out.Phase, out.ReasonCode = recordingGroupPhase(out.Actions)
	out.CanCancel = out.CanCancel && !out.CancellationRequested
	if history, err := q.ReadRecordingGroupHistoryFacts(ctx, custodydb.ReadRecordingGroupHistoryFactsParams{RootID: header.RootID, CaptureID: header.ID}); err == nil {
		if history.Visible && history.State == "available" && history.CustodyState == artifact.StoredUnpublished && observedAt.Before(history.SummaryExpiresAt.Time) && observedAt.Before(history.EffectiveExpiresAt.Time) {
			out.HistoryState = "available"
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return zero, err
	}
	if err := s.recovery.check(ctx, q, recovery, s.root, request.Recovery); err != nil {
		return zero, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil || !request.Valid(now.Time) || !out.Valid(now.Time) {
		return zero, value.ErrDenied
	}
	return out, ctx.Err()
}
