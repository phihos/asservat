package privacy

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type ProcessingErasureAuditState string

const (
	ProcessingErasureAuditPending      ProcessingErasureAuditState = "pending"
	ProcessingErasureAuditAcknowledged ProcessingErasureAuditState = "acknowledged"
)

type ProcessingErasureDeletionState string

const (
	ProcessingErasureDeletionPending ProcessingErasureDeletionState = "pending"
	ProcessingErasureDeletionOverdue ProcessingErasureDeletionState = "overdue"
	ProcessingErasureDeleted         ProcessingErasureDeletionState = "deleted"
)

// ProcessingErasureStatus describes an applied request. DeleteBy is the hard
// cutoff retained at acceptance. Further shortening only affects EffectiveDeleteBy.
// The audit state is for the lifecycle record. A deleted state means managed
// evidence finalization was independently acknowledged by the custody path.
type ProcessingErasureStatus struct {
	RequestID         string                         `json:"request_id"`
	ArtifactID        string                         `json:"artifact_id"`
	AcceptedAt        time.Time                      `json:"accepted_at"`
	AccessUntil       time.Time                      `json:"access_until"`
	DeleteBy          time.Time                      `json:"delete_by"`
	EffectiveDeleteBy time.Time                      `json:"effective_delete_by"`
	AuditState        ProcessingErasureAuditState    `json:"audit_state"`
	DeletionState     ProcessingErasureDeletionState `json:"deletion_state"`
	DeletedAt         *time.Time                     `json:"deleted_at,omitempty"`
	ObservedAt        time.Time                      `json:"-"`
	ValidUntil        time.Time                      `json:"-"`
}

func (s ProcessingErasureStatus) Valid(requestID string, now time.Time) bool {
	window := identity.Check(s.ObservedAt, identity.SQLFenced).Narrow(s.ValidUntil)
	if !authorization.UUID(s.RequestID) || s.RequestID != requestID || !authorization.UUID(s.ArtifactID) ||
		!window.Valid(now) || !window.Until().Equal(s.ValidUntil) || !finiteTime(s.AcceptedAt) ||
		!finiteTime(s.AccessUntil) || s.AcceptedAt.Before(s.AccessUntil) ||
		!finiteTime(s.DeleteBy) || !finiteTime(s.EffectiveDeleteBy) || !s.EffectiveDeleteBy.After(s.AccessUntil) ||
		s.EffectiveDeleteBy.After(s.DeleteBy) ||
		s.AuditState != ProcessingErasureAuditPending && s.AuditState != ProcessingErasureAuditAcknowledged {
		return false
	}
	switch s.DeletionState {
	case ProcessingErasureDeletionPending:
		return s.DeletedAt == nil && now.Before(s.EffectiveDeleteBy) && !s.ValidUntil.After(s.EffectiveDeleteBy)
	case ProcessingErasureDeletionOverdue:
		return s.DeletedAt == nil && !now.Before(s.EffectiveDeleteBy)
	case ProcessingErasureDeleted:
		return s.DeletedAt != nil && finiteTime(*s.DeletedAt) && !s.DeletedAt.Before(s.AcceptedAt)
	default:
		return false
	}
}
