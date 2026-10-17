package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
)

// This regression also compiles against the original acknowledgement-only
// acceptedPublication implementation. Positive fixture receipts are concrete
// synthetic metadata, never an implementation of production authority.
func contextReceiptFixture(t *testing.T, operation bool) custodydb.ContextCapture {
	t.Helper()
	c := progressFactsFixture(t, "audited").ContextCapture
	key := audit.CaptureIntentKey(uid(c.RootID), uid(c.ID))
	if operation {
		c.IntentOperationID = c.ID
		key = audit.OperationAuditKey(uid(c.RootID), uid(c.ID), "intent")
	}
	c.IntentObjectKey = pgtype.Text{String: key, Valid: true}
	c.IntentObjectVersion = pgtype.Text{String: "synthetic-version", Valid: true}
	c.IntentObjectEtag = pgtype.Text{String: "synthetic-etag", Valid: true}
	c.IntentObjectBytes = pgtype.Int8{Int64: 128, Valid: true}
	c.IntentObjectSha256 = digest("synthetic-audit")
	return c
}
func TestAcceptedPublicationRequiresRetainedIntentReceipt(t *testing.T) {
	for _, operation := range []bool{false, true} {
		family := "legacy"
		if operation {
			family = "operation"
		}
		t.Run(family, func(t *testing.T) {
			c := contextReceiptFixture(t, operation)
			if _, e := acceptedPublication(c); e != nil {
				t.Fatal("positive original receipt", e)
			}
			for name, mutate := range map[string]func(*custodydb.ContextCapture){
				"empty":     func(c *custodydb.ContextCapture) { c.IntentObjectVersion.String = "" },
				"null":      func(c *custodydb.ContextCapture) { c.IntentObjectVersion.String = "null" },
				"sql-null":  func(c *custodydb.ContextCapture) { c.IntentObjectVersion.Valid = false },
				"wrong-key": func(c *custodydb.ContextCapture) { c.IntentObjectKey.String += "/other" },
				"wrong-protocol": func(c *custodydb.ContextCapture) {
					if operation {
						c.IntentObjectKey.String = audit.CaptureIntentKey(uid(c.RootID), uid(c.ID))
					} else {
						c.IntentObjectKey.String = audit.OperationAuditKey(uid(c.RootID), uid(c.ID), "intent")
					}
				},
				"zero-hash":      func(c *custodydb.ContextCapture) { c.IntentObjectSha256 = make([]byte, 32) },
				"truncated-hash": func(c *custodydb.ContextCapture) { c.IntentObjectSha256 = c.IntentObjectSha256[:31] },
				"zero-bytes":     func(c *custodydb.ContextCapture) { c.IntentObjectBytes.Int64 = 0 },
			} {
				t.Run(name, func(t *testing.T) {
					bad := c
					mutate(&bad)
					if _, e := acceptedPublication(bad); e == nil {
						t.Fatal("historical or nonmatching receipt authorized current publication")
					}
				})
			}
		})
	}
}
