package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"bytes"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
)

func publishedReceiptFixture(t *testing.T) custodydb.ReadPublishedContextRow {
	t.Helper()
	f := progressFactsFixture(t, "published")
	c := f.ContextCapture
	v := custodydb.ContextVerification{CaptureID: c.ID, RootID: c.RootID, VerifiedAt: f.VerifiedAt, ExpectationDigest: f.ExpectationDigest, CopiesDigest: f.VerifiedCopiesDigest, IntentDigest: f.VerifiedIntentDigest, AuthorityDigest: f.AuthorityDigest, PermissionEpoch: f.PermissionEpoch, PermissionSequence: f.PermissionSequence.Int64, AuditAcknowledgedAt: f.AuditAcknowledgedAt, AuditDigest: f.AuditDigest}
	v.AuditObjectKey = pgtype.Text{String: audit.ContextVerificationKey(uid(c.RootID), uid(c.ID)), Valid: true}
	v.AuditObjectVersion = pgtype.Text{String: "synthetic-original", Valid: true}
	v.AuditObjectEtag = pgtype.Text{String: "synthetic-etag", Valid: true}
	v.AuditObjectBytes = pgtype.Int8{Int64: 128, Valid: true}
	v.AuditObjectSha256 = digest("synthetic-verification-receipt")
	return custodydb.ReadPublishedContextRow{ContextCapture: c, ContextVerification: v, PublishedAt: f.PublishedAt, EffectiveExpiresAt: f.EffectiveExpiresAt, EffectiveDeleteBy: f.EffectiveDeleteBy}
}
func TestCurrentCatalogRequiresBothOriginalAuditReceipts(t *testing.T) {
	row := publishedReceiptFixture(t)
	if _, e := currentPublishedContext(row); e != nil {
		t.Fatal("original committed context", e)
	}
	for name, mutate := range map[string]func(*custodydb.ReadPublishedContextRow){
		"intent-empty":          func(r *custodydb.ReadPublishedContextRow) { r.ContextCapture.IntentObjectVersion.String = "" },
		"intent-null":           func(r *custodydb.ReadPublishedContextRow) { r.ContextCapture.IntentObjectVersion.String = "null" },
		"verification-empty":    func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectVersion.String = "" },
		"verification-null":     func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectVersion.String = "null" },
		"verification-sql-null": func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectVersion.Valid = false },
		"verification-key":      func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectKey.String += "-other" },
		"verification-hash":     func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectSha256 = make([]byte, 32) },
		"verification-hash-size": func(r *custodydb.ReadPublishedContextRow) {
			r.ContextVerification.AuditObjectSha256 = r.ContextVerification.AuditObjectSha256[:31]
		},
		"verification-etag":   func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectEtag.Valid = false },
		"verification-bytes":  func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditObjectBytes.Int64 = 0 },
		"verification-record": func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.AuditDigest = make([]byte, 32) },
		"intent-record":       func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.IntentDigest = digest("other") },
		"capture":             func(r *custodydb.ReadPublishedContextRow) { r.ContextVerification.CaptureID = r.ContextCapture.RootID },
		"early-publication":   func(r *custodydb.ReadPublishedContextRow) { r.PublishedAt = r.ContextVerification.VerifiedAt },
	} {
		t.Run(name, func(t *testing.T) {
			bad := row
			mutate(&bad)
			if _, e := currentPublishedContext(bad); e == nil {
				t.Fatal("unversioned or changed retained catalog authorized current access")
			}
		})
	}
}
func TestUnversionedHistoryRemainsHistoricalProgress(t *testing.T) {
	for _, version := range []string{"", "null"} {
		f := progressFactsFixture(t, "published")
		f.ContextCapture.IntentObjectVersion.String = version
		before := digest(f)
		if _, e := acceptedPublication(f.ContextCapture); e == nil {
			t.Fatal("historical acknowledgement became current authority")
		}
		got, e := progressFacts(f)
		if e != nil || got.Phase != "Succeeded" || !bytes.Equal(digest(f), before) {
			t.Fatal("historical outcome lost or mutated", e)
		}
	}
}
