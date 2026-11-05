package postgres

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/migrations"
)

func TestRawPacketProjectionPublishedSourcePinsRawAndBound(t *testing.T) {
	s := analysis.ContextProjectionScope{NativeType: artifact.RawPCAPNGArtifact, SourceFormat: artifact.RawPCAPNGFormat, DisplayVersion: "approved-raw-pcap-summary/v1"}
	for _, limit := range []int64{1, 1 << 20, artifact.RecordingNativeLimit} {
		e := artifact.ContextExpectation{NativeType: artifact.RawPCAPNGArtifact, DataClass: "raw", Registration: artifact.Registration{NativeLimit: limit}}
		r := app.ContextProjectionEvidence{NativeType: e.NativeType, SourceFormat: artifact.RawPCAPNGFormat, DataClass: e.DataClass, Retained: privacy.RetainedArtifact{Registration: e.Registration, Input: privacy.Input{EvidenceType: "packetCapture"}}}
		if !scopeSource(s, e) || !projectionSource(r) {
			t.Fatal("published raw source refused", limit)
		}
		for _, class := range []string{"metadata", "extract", ""} {
			badE, badR := e, r
			badE.DataClass, badR.DataClass = class, class
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("raw source reclassified", class)
			}
		}
		for _, n := range []int64{0, artifact.RecordingNativeLimit + 1} {
			badE, badR := e, r
			badE.Registration.NativeLimit, badR.Retained.Registration.NativeLimit = n, n
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("unbounded raw source accepted", n)
			}
		}
		badScope := s
		badScope.DisplayVersion = analysis.PacketSummaryDisplayVersion
		if scopeSource(badScope, e) {
			t.Fatal("raw source accepted metadata display")
		}
		badR := r
		badR.Retained.Input.EvidenceType = "profile"
		if projectionSource(badR) {
			t.Fatal("unrelated evidence type accepted")
		}
		badR = r
		badR.SourceProjectionDigest = artifact.Digest{1}
		if projectionSource(badR) {
			t.Fatal("projection digest accepted")
		}
	}
}

func TestRawPacketMigrationRestoresExactPreviousFunctions(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"context_query_scope_source_valid", "context_query_begin_tool", "context_query_read_batches", "context_query_units", "guard_context_query"}
	old := map[string]string{}
	for _, name := range files {
		if name >= "00138_raw_packet_summary.sql" {
			continue
		}
		b, e := fs.ReadFile(migrations.Files(), name)
		if e != nil {
			t.Fatal(e)
		}
		up, _, _ := strings.Cut(string(b), "-- +goose Down")
		for _, f := range names {
			re := regexp.MustCompile(`(?s)CREATE (?:OR REPLACE )?FUNCTION ` + regexp.QuoteMeta(f) + `\(.*?-- \+goose StatementEnd`)
			if m := re.FindString(up); m != "" {
				old[f] = m
			}
		}
	}
	b, err := fs.ReadFile(migrations.Files(), "00138_raw_packet_summary.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down")
	}
	for _, f := range names {
		re := regexp.MustCompile(`(?s)CREATE OR REPLACE FUNCTION ` + regexp.QuoteMeta(f) + `\(.*?-- \+goose StatementEnd`)
		if old[f] == "" || re.FindString(down) != old[f] {
			t.Fatal("Down changed original function", f)
		}
	}
	if !strings.Contains(down, "raw packet query history cannot be downgraded") || !strings.Contains(down, "intent->>'Name'='get_pcap_summary'") || !strings.Contains(down, "NativeType'='rawPcapng'") {
		t.Fatal("retained raw query/audit guard missing")
	}
	if strings.Contains(up, "CREATE TABLE") || strings.Contains(up, "GRANT ") {
		t.Fatal("unexpected new state/privileges")
	}
}
