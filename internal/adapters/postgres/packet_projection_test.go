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

func TestPacketProjectionPublishedSourcePinsMetadataAndBound(t *testing.T) {
	s := analysis.ContextProjectionScope{NativeType: artifact.PCAPNGArtifact, SourceFormat: artifact.PCAPNGFormat, DisplayVersion: analysis.PacketSummaryDisplayVersion}
	for _, limit := range []int64{1, 1 << 20, artifact.RecordingNativeLimit} {
		e := artifact.ContextExpectation{NativeType: artifact.PCAPNGArtifact, DataClass: "metadata", Registration: artifact.Registration{NativeLimit: limit}}
		r := app.ContextProjectionEvidence{NativeType: e.NativeType, SourceFormat: artifact.PCAPNGFormat, DataClass: e.DataClass, Retained: privacy.RetainedArtifact{Registration: e.Registration, Input: privacy.Input{EvidenceType: "packetCapture"}}}
		if !scopeSource(s, e) || !projectionSource(r) {
			t.Fatal("published metadata source refused", limit)
		}
		for _, badLimit := range []int64{0, artifact.RecordingNativeLimit + 1} {
			badE, badR := e, r
			badE.Registration.NativeLimit = badLimit
			badR.Retained.Registration.NativeLimit = badLimit
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("unbounded source accepted", badLimit)
			}
		}
		for _, class := range []string{"raw", "extract", ""} {
			badE, badR := e, r
			badE.DataClass = class
			badR.DataClass = class
			if scopeSource(s, badE) || projectionSource(badR) {
				t.Fatal("source reclassified", class)
			}
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
		badE, badR := e, r
		badE.NativeType = artifact.RawPCAPNGArtifact
		badR.NativeType = artifact.RawPCAPNGArtifact
		badR.SourceFormat = artifact.RawPCAPNGFormat
		if scopeSource(s, badE) || projectionSource(badR) {
			t.Fatal("raw packets reclassified metadata")
		}
	}
}

func TestSavedPacketMigrationRestoresExactPreviousFunctions(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	functions := []string{"context_query_scope_source_valid", "context_query_begin_tool", "context_query_read_batches", "context_query_units", "operation_audit_lane", "operation_audit_human_input_valid", "guard_operation_audit", "context_query_intent_current", "context_query_outcome_closed", "guard_context_query"}
	old := map[string]string{}
	for _, name := range files {
		if name >= "00137_saved_packet_summary.sql" {
			continue
		}
		b, err := fs.ReadFile(migrations.Files(), name)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(b), "-- +goose Down")
		for _, f := range functions {
			re := regexp.MustCompile(`(?s)CREATE (?:OR REPLACE )?FUNCTION ` + regexp.QuoteMeta(f) + `\(.*?-- \+goose StatementEnd`)
			if m := re.FindString(up); m != "" {
				old[f] = m
			}
		}
	}
	b, err := fs.ReadFile(migrations.Files(), "00137_saved_packet_summary.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("missing Down")
	}
	for _, f := range functions {
		re := regexp.MustCompile(`(?s)CREATE OR REPLACE FUNCTION ` + regexp.QuoteMeta(f) + `\(.*?-- \+goose StatementEnd`)
		if old[f] == "" || re.FindString(down) != old[f] {
			t.Fatal("Down changed original function", f)
		}
	}
	if !strings.Contains(down, "saved packet query history cannot be downgraded") || !strings.Contains(down, "intent->>'Name'='get_pcap_summary'") {
		t.Fatal("retained query/audit guard missing")
	}
	if strings.Contains(up, "CREATE TABLE") || strings.Contains(up, "GRANT ") {
		t.Fatal("unexpected new state/privileges")
	}
}
