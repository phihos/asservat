package postgres

import (
	"time"

	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// This is immutable post-admission bookkeeping, not a longer observation or
// commit permit. The caller retains the original proof bound in OriginalUntil
// and repeats all admission checks after these writes.
func recordingGroupAuditUntil(bounds value.GroupRequestBounds, a value.Admission, intent audit.CaptureIntent, hardEnds ...time.Time) (time.Time, error) {
	s := a.Plan.Input.Snapshot
	if a.RecordingSave == nil || s == nil || s.Group == nil || intent.Group == nil || !bounds.Valid(intent.CreatedAt) || bounds.Requester != a.Requester() || bounds.Requester != intent.Requester() || s.TriggerKind != "recordingSave" || !s.Request.T0.Equal(intent.CreatedAt) || s.Group.ChildCount < 2 || s.Group.ChildCount > 16 || s.Group.ChildIndex < 0 || s.Group.ChildIndex >= s.Group.ChildCount || s.Group.SelectionDigest != intent.Group.SelectionDigest || s.Group.ParentCaptureID != intent.Group.ParentCaptureID || s.Group.ChildIndex != intent.Group.ChildIndex || s.Group.ChildCount != intent.Group.ChildCount {
		return time.Time{}, value.ErrDenied
	}
	until := identity.Earlier(bounds.Until, identity.Earlier(s.Request.StartBy, identity.Earlier(s.Request.SourceHardUntil, identity.Earlier(a.Registration.WriteUntil, intent.Deadline))))
	for _, end := range hardEnds {
		if end.IsZero() {
			return time.Time{}, value.ErrUnavailable
		}
		until = identity.Earlier(until, end)
	}
	until = until.UTC().Truncate(time.Microsecond)
	if !intent.CreatedAt.Before(until) {
		return time.Time{}, value.ErrDenied
	}
	return until, nil
}
