package postgres

import (
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestExactCaptureIntentReceiptRejectsSubstitution(t *testing.T) {
	for _, mode := range []string{"acknowledged", "pending", "wrong-key", "wrong-digest", "incomplete-receipt", "truncated-cipher-hash", "false-state", "pending-receipt"} {
		t.Run(mode, func(t *testing.T) {
			row := progressFactsFixture(t, "pending").ContextCapture
			r, err := captureIntent(row)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "pending" {
				row.State = "intent_audited"
				row.IntentAcknowledgedAt = ts(row.CreatedAt.Time)
				row.IntentDigest = digest(r)
				row.IntentObjectKey = pgtype.Text{String: audit.CaptureIntentKey(r.RootID, r.CaptureID), Valid: true}
				row.IntentObjectVersion = pgtype.Text{String: "synthetic-version", Valid: true}
				row.IntentObjectEtag = pgtype.Text{String: "synthetic", Valid: true}
				row.IntentObjectBytes = pgtype.Int8{Int64: 100, Valid: true}
				d := artifact.Digest{1}
				row.IntentObjectSha256 = d[:]
			}
			switch mode {
			case "wrong-key":
				row.IntentObjectKey.String = "other"
			case "wrong-digest":
				row.IntentDigest = digest("other")
			case "incomplete-receipt":
				row.IntentObjectVersion.Valid = false
			case "truncated-cipher-hash":
				row.IntentObjectSha256 = row.IntentObjectSha256[:31]
			case "false-state":
				row.State = "accepted_pending_audit"
			case "pending-receipt":
				row.State = "accepted_pending_audit"
				row.IntentAcknowledgedAt.Valid = false
			}
			got, err := exactCaptureIntent(row)
			if mode != "acknowledged" && mode != "pending" {
				if err == nil {
					t.Fatal("invalid exact receipt accepted")
				}
				return
			}
			if err != nil || got.Intent != r || (got.Receipt != nil) != (mode == "acknowledged") {
				t.Fatal("exact intent lost", err)
			}
		})
	}
}

// Keep the generated exact selector's parameter contract visible at compile
// time; native qualification must additionally use the real SELECT-only role.
var _ = custodydb.ReadExactCaptureIntentParams{}
