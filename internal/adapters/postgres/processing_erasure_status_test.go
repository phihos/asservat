package postgres

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/privacy"
)

func TestProcessingErasureProjectionSeparatesAuditFromVerifiedDeletion(t *testing.T) {
	const requestID = "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	original := now.Add(time.Hour)
	earlier := now.Add(2 * time.Second)
	for _, name := range []string{"pending", "overdue", "deleted-audit-pending", "false-deleted", "invalid-receipt", "retired"} {
		t.Run(name, func(t *testing.T) {
			row := custodydb.ReadAppliedProcessingErasureRow{
				ID: id(requestID), ArtifactID: id("00000000-0000-4000-8000-000000000002"),
				AppliedAt: ts(now.Add(-time.Minute)), RetireBy: ts(now.Add(24 * time.Hour)),
				AccessUntil: ts(now.Add(-time.Hour)), DeleteBy: ts(original), EffectiveDeleteBy: ts(earlier),
				CustodyState: "deleting",
			}
			audit := value.ProcessingErasureAuditPending
			deletion := value.ProcessingErasureDeletionPending
			until := earlier
			switch name {
			case "overdue":
				row.EffectiveDeleteBy = ts(now)
				row.AuditReceiptCurrent, row.AuditAcknowledgedAt = true, ts(now)
				deletion, audit, until = value.ProcessingErasureDeletionOverdue, value.ProcessingErasureAuditAcknowledged, now.Add(5*time.Second)
			case "deleted-audit-pending":
				row.CustodyState, row.DeletedAt = "deleted", ts(now)
				deletion, until = value.ProcessingErasureDeleted, now.Add(5*time.Second)
			case "false-deleted":
				row.CustodyState = "deleted"
			case "invalid-receipt":
				row.AuditAcknowledgedAt = ts(now)
			case "retired":
				row.RetireBy = ts(now)
			}
			out, err := projectProcessingErasureStatus(row, requestID, now, now.Add(5*time.Second), now)
			if name == "false-deleted" || name == "invalid-receipt" || name == "retired" {
				if err == nil || out != (value.ProcessingErasureStatus{}) {
					t.Fatal("unverified state projected", out, err)
				}
				return
			}
			if err != nil || out.DeletionState != deletion || out.AuditState != audit ||
				!out.DeleteBy.Equal(original) || !out.EffectiveDeleteBy.Equal(row.EffectiveDeleteBy.Time) ||
				!out.ValidUntil.Equal(until) || (out.DeletedAt != nil) != row.DeletedAt.Valid {
				t.Fatal("status conflated acknowledgement, deadline and terminal state", out, err)
			}
		})
	}
}
