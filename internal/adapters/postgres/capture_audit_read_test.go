package postgres

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestCaptureOperationRetainedReceiptRequiresExactNewProtocol(t *testing.T) {
	for _, mode := range []string{"acknowledged", "pending", "legacy", "other-operation", "wrong-key", "wrong-digest", "incomplete", "truncated", "false-state", "pending-receipt", "late-ack"} {
		t.Run(mode, func(t *testing.T) {
			row := progressFactsFixture(t, "pending").ContextCapture
			row.IntentOperationID = row.ID
			in, e := captureIntent(row)
			if e != nil {
				t.Fatal(e)
			}
			if mode != "pending" {
				row.State = "intent_audited"
				row.IntentAcknowledgedAt = ts(row.CreatedAt.Time)
				row.IntentDigest = digest(in)
				row.IntentObjectKey = pgtype.Text{String: value.OperationAuditKey(in.RootID, in.CaptureID, "intent"), Valid: true}
				row.IntentObjectVersion = pgtype.Text{String: "synthetic-version", Valid: true}
				row.IntentObjectEtag = pgtype.Text{String: "synthetic", Valid: true}
				row.IntentObjectBytes = pgtype.Int8{Int64: 100, Valid: true}
				d := artifact.Digest{1}
				row.IntentObjectSha256 = d[:]
			}
			switch mode {
			case "legacy":
				row.IntentOperationID.Valid = false
			case "other-operation":
				row.IntentOperationID = row.RootID
			case "wrong-key":
				row.IntentObjectKey.String = value.CaptureIntentKey(in.RootID, in.CaptureID)
			case "wrong-digest":
				row.IntentDigest = digest("other")
			case "incomplete":
				row.IntentObjectVersion.Valid = false
			case "truncated":
				row.IntentObjectSha256 = row.IntentObjectSha256[:31]
			case "false-state":
				row.State = "accepted_pending_audit"
			case "pending-receipt":
				row.State = "accepted_pending_audit"
				row.IntentAcknowledgedAt.Valid = false
			case "late-ack":
				row.IntentAcknowledgedAt = ts(in.CreatedAt.Add(30 * time.Second))
			}
			got, e := exactCaptureOperationIntent(row)
			if mode != "acknowledged" && mode != "pending" {
				if e == nil {
					t.Fatal("invalid new-protocol receipt accepted")
				}
				return
			}
			if e != nil || got.Intent != in || got.OperationID != in.CaptureID || (got.Receipt != nil) != (mode == "acknowledged") {
				t.Fatal("retained exact acknowledgement changed", e)
			}
		})
	}
}
