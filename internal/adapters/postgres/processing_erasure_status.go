package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

var _ app.ProcessingErasureStatusReader = (*ProcessingDecisions)(nil)

func (s *ProcessingDecisions) ReadProcessingErasureStatus(ctx context.Context, a value.ProcessingAuthority, requestID string) (value.ProcessingErasureStatus, error) {
	var out value.ProcessingErasureStatus
	if s == nil || !authorization.UUID(requestID) {
		return out, value.ErrUnavailable
	}
	err := s.transaction(ctx, a, func(call context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, _ time.Time) error {
		if !p.InitializedAt.Valid {
			return value.ErrUnavailable
		}
		row, err := q.ReadAppliedProcessingErasure(call, custodydb.ReadAppliedProcessingErasureParams{RootID: p.RootID, RequestID: id(requestID)})
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(call)
		if err != nil {
			return err
		}
		until := identity.Earlier(a.ValidUntil, p.ValidUntil.Time)
		out, err = projectProcessingErasureStatus(row, requestID, a.ObservedAt, until, now.Time)
		return err
	})
	if err != nil {
		return value.ProcessingErasureStatus{}, value.ErrUnavailable
	}
	return out, nil
}

func projectProcessingErasureStatus(row custodydb.ReadAppliedProcessingErasureRow, requestID string, observed, until, now time.Time) (value.ProcessingErasureStatus, error) {
	var zero value.ProcessingErasureStatus
	if !row.AppliedAt.Valid || row.AppliedAt.Time.After(now) || !row.RetireBy.Valid ||
		!row.AccessUntil.Valid || !row.DeleteBy.Valid || !row.EffectiveDeleteBy.Valid ||
		row.AuditAcknowledgedAt.Valid != row.AuditReceiptCurrent ||
		row.AuditAcknowledgedAt.Valid && (row.AuditAcknowledgedAt.Time.Before(row.AppliedAt.Time) || row.AuditAcknowledgedAt.Time.After(now)) {
		return zero, value.ErrUnavailable
	}
	out := value.ProcessingErasureStatus{
		RequestID: uid(row.ID), ArtifactID: uid(row.ArtifactID), AcceptedAt: row.AppliedAt.Time,
		AccessUntil: row.AccessUntil.Time, DeleteBy: row.DeleteBy.Time, EffectiveDeleteBy: row.EffectiveDeleteBy.Time,
		AuditState: value.ProcessingErasureAuditPending, ObservedAt: observed, ValidUntil: identity.Earlier(until, row.RetireBy.Time),
	}
	if row.AuditReceiptCurrent {
		out.AuditState = value.ProcessingErasureAuditAcknowledged
	}
	switch row.CustodyState {
	case "stored_unpublished", "deleting":
		if row.DeletedAt.Valid {
			return zero, value.ErrUnavailable
		}
		out.DeletionState = value.ProcessingErasureDeletionOverdue
		if now.Before(out.EffectiveDeleteBy) {
			out.DeletionState = value.ProcessingErasureDeletionPending
			out.ValidUntil = identity.Earlier(out.ValidUntil, out.EffectiveDeleteBy)
		}
	case "deleted":
		// Erasure admission proves the closed writer protocol. Its custody
		// transition to deleted requires the independent audited purge trigger.
		if !row.DeletedAt.Valid || row.DeletedAt.Time.After(now) {
			return zero, value.ErrUnavailable
		}
		out.DeletionState, out.DeletedAt = value.ProcessingErasureDeleted, &row.DeletedAt.Time
	default:
		return zero, value.ErrUnavailable
	}
	if !out.Valid(requestID, now) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
