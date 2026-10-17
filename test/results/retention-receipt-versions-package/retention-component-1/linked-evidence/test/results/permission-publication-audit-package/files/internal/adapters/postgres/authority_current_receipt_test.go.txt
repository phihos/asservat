package postgres

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCurrentAuthorityAuditRequiresExactImmutableReceipt(t *testing.T) {
	root := id("20000000-0000-4000-8000-000000000001")
	event := id("20000000-0000-4000-8000-000000000002")
	other := id("20000000-0000-4000-8000-000000000003")
	row := custodydb.AuthorityAudit{
		ID: event, StreamID: root, AcknowledgedAt: ts(time.Now()),
		ObjectKey:     pgtype.Text{String: audit.AuthorityKey(uid(root), uid(event)), Valid: true},
		ObjectVersion: pgtype.Text{String: "original-version", Valid: true},
		ObjectEtag:    pgtype.Text{String: "original-etag", Valid: true},
		ObjectBytes:   pgtype.Int8{Int64: 1024, Valid: true}, ObjectSha256: bytes.Repeat([]byte{1}, 32),
		Record: []byte("structural historical record is independently decoded"),
	}
	for _, tc := range []struct {
		name   string
		change func(*custodydb.AuthorityAudit)
		want   bool
	}{
		{"original", func(*custodydb.AuthorityAudit) {}, true},
		{"empty-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.String = "" }, false},
		{"null-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.String = "null" }, false},
		{"absent-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.Valid = false }, false},
		{"maximum-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.String = strings.Repeat("v", 1024) }, true},
		{"oversized-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.String = strings.Repeat("v", 1025) }, false},
		{"control-version", func(r *custodydb.AuthorityAudit) { r.ObjectVersion.String = "v\n" }, false},
		{"unacknowledged", func(r *custodydb.AuthorityAudit) { r.AcknowledgedAt.Valid = false }, false},
		{"different-root", func(r *custodydb.AuthorityAudit) { r.StreamID = other }, false},
		{"different-event", func(r *custodydb.AuthorityAudit) { r.ID = other }, false},
		{"different-key", func(r *custodydb.AuthorityAudit) { r.ObjectKey.String += "other" }, false},
		{"missing-key", func(r *custodydb.AuthorityAudit) { r.ObjectKey.Valid = false }, false},
		{"missing-etag", func(r *custodydb.AuthorityAudit) { r.ObjectEtag.Valid = false }, false},
		{"empty-etag", func(r *custodydb.AuthorityAudit) { r.ObjectEtag.String = "" }, false},
		{"absent-bytes", func(r *custodydb.AuthorityAudit) { r.ObjectBytes.Valid = false }, false},
		{"empty-bytes", func(r *custodydb.AuthorityAudit) { r.ObjectBytes.Int64 = 0 }, false},
		{"excess-bytes", func(r *custodydb.AuthorityAudit) { r.ObjectBytes.Int64 = 16<<20 + 1 }, false},
		{"short-digest", func(r *custodydb.AuthorityAudit) { r.ObjectSha256 = r.ObjectSha256[:31] }, false},
		{"long-digest", func(r *custodydb.AuthorityAudit) { r.ObjectSha256 = append(r.ObjectSha256, 1) }, false},
		{"zero-digest", func(r *custodydb.AuthorityAudit) { clear(r.ObjectSha256) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := row
			changed.Record = bytes.Clone(row.Record)
			changed.ObjectSha256 = bytes.Clone(row.ObjectSha256)
			tc.change(&changed)
			before, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if got := currentAuthorityAudit(changed, root, event); got != tc.want {
				t.Fatalf("current receipt authority=%v, want %v", got, tc.want)
			}
			after, err := json.Marshal(changed)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("current check rewrote historical input", err)
			}
		})
	}
	if currentAuthorityAudit(row, pgtype.UUID{}, event) || currentAuthorityAudit(row, root, pgtype.UUID{}) {
		t.Fatal("absent original scope accepted")
	}
}
