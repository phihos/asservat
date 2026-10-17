package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"bytes"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"testing"
	"time"
)

func TestCurrentBootstrapIntentAudit(t *testing.T) {
	root := id("30000000-0000-4000-8000-000000000001")
	event := id("30000000-0000-4000-8000-000000000002")
	row := custodydb.FleetBootstrapIntent{InstallationID: root, ID: event, AuditAcknowledgedAt: ts(time.Now()), AuditObjectKey: pgtype.Text{String: audit.BootstrapIssueKey(uid(root), uid(event)), Valid: true}, AuditObjectVersion: pgtype.Text{String: "version-1", Valid: true}, AuditObjectEtag: pgtype.Text{String: "etag-1", Valid: true}, AuditObjectBytes: pgtype.Int8{Int64: 1024, Valid: true}, AuditObjectSha256: bytes.Repeat([]byte{1}, 32)}
	for _, tc := range []struct {
		name   string
		change func(*custodydb.FleetBootstrapIntent)
		want   bool
	}{
		{"original", func(*custodydb.FleetBootstrapIntent) {}, true},
		{"empty-version", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectVersion.String = "" }, false},
		{"literal-null", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectVersion.String = "null" }, false},
		{"absent-version", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectVersion.Valid = false }, false},
		{"different-root", func(r *custodydb.FleetBootstrapIntent) { r.InstallationID = event }, false},
		{"different-event", func(r *custodydb.FleetBootstrapIntent) { r.ID = root }, false},
		{"missing-key", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectKey.Valid = false }, false},
		{"unacknowledged", func(r *custodydb.FleetBootstrapIntent) { r.AuditAcknowledgedAt.Valid = false }, false},
		{"missing-etag", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectEtag.Valid = false }, false},
		{"empty-etag", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectEtag.String = "" }, false},
		{"absent-bytes", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectBytes.Valid = false }, false},
		{"zero-bytes", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectBytes.Int64 = 0 }, false},
		{"maximum-bytes", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectBytes.Int64 = 128 << 10 }, true},
		{"oversized-bytes", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectBytes.Int64 = 128<<10 + 1 }, false},
		{"short-hash", func(r *custodydb.FleetBootstrapIntent) { r.AuditObjectSha256 = r.AuditObjectSha256[:31] }, false},
		{"zero-hash", func(r *custodydb.FleetBootstrapIntent) { clear(r.AuditObjectSha256) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := row
			r.AuditObjectSha256 = bytes.Clone(row.AuditObjectSha256)
			tc.change(&r)
			before, _ := json.Marshal(r)
			if currentBootstrapIntentAudit(r) != tc.want {
				t.Fatal("unexpected current receipt decision")
			}
			after, _ := json.Marshal(r)
			if !bytes.Equal(before, after) {
				t.Fatal("historical row rewritten")
			}
		})
	}
}

func TestCurrentIssuedBootstrapAudit(t *testing.T) {
	root := id("30000000-0000-4000-8000-000000000001")
	event := id("30000000-0000-4000-8000-000000000002")
	row := custodydb.FleetBootstrap{InstallationID: root, IssueAuditID: event, IssueAuditKey: audit.BootstrapIssueKey(uid(root), uid(event)), IssueAuditVersion: "version-1", IssueAuditSha256: bytes.Repeat([]byte{1}, 32), IssueAuthorityDigest: bytes.Repeat([]byte{2}, 32)}
	for _, tc := range []struct {
		name   string
		change func(*custodydb.FleetBootstrap)
		want   bool
	}{
		{"original", func(*custodydb.FleetBootstrap) {}, true},
		{"empty-version", func(r *custodydb.FleetBootstrap) { r.IssueAuditVersion = "" }, false},
		{"literal-null", func(r *custodydb.FleetBootstrap) { r.IssueAuditVersion = "null" }, false},
		{"maximum-version", func(r *custodydb.FleetBootstrap) { r.IssueAuditVersion = strings.Repeat("v", 1024) }, true},
		{"oversized-version", func(r *custodydb.FleetBootstrap) { r.IssueAuditVersion = strings.Repeat("v", 1025) }, false},
		{"different-root", func(r *custodydb.FleetBootstrap) { r.InstallationID = event }, false},
		{"different-event", func(r *custodydb.FleetBootstrap) { r.IssueAuditID = root }, false},
		{"missing-key", func(r *custodydb.FleetBootstrap) { r.IssueAuditKey = "" }, false},
		{"short-hash", func(r *custodydb.FleetBootstrap) { r.IssueAuditSha256 = r.IssueAuditSha256[:31] }, false},
		{"zero-hash", func(r *custodydb.FleetBootstrap) { clear(r.IssueAuditSha256) }, false},
		{"short-authority-digest", func(r *custodydb.FleetBootstrap) { r.IssueAuthorityDigest = r.IssueAuthorityDigest[:31] }, false},
		{"zero-authority-digest", func(r *custodydb.FleetBootstrap) { clear(r.IssueAuthorityDigest) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := row
			r.IssueAuditSha256 = bytes.Clone(row.IssueAuditSha256)
			r.IssueAuthorityDigest = bytes.Clone(row.IssueAuthorityDigest)
			tc.change(&r)
			before, _ := json.Marshal(r)
			if currentIssuedBootstrapAudit(r) != tc.want {
				t.Fatal("unexpected current receipt decision")
			}
			after, _ := json.Marshal(r)
			if !bytes.Equal(before, after) {
				t.Fatal("historical row rewritten")
			}
		})
	}
}
