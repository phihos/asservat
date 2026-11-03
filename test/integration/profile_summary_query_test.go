package integration

import (
	"context"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

// Actual migration functions, not installed query authority or a parser run.
func qualifyProfileSummaryQueryFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	id := custodyID()
	scope := analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: artifact.PprofArtifact, SourceFormat: artifact.PprofFormat, DisplayVersion: analysis.ProfileSummaryDisplayVersion, Profile: analysis.ProfileSummarySelection{SampleType: "cpu", TopN: 20}, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}}
	if !scope.Valid() {
		t.Fatal("invalid synthetic summary scope")
	}
	for _, mode := range []string{"valid", "top", "sample", "extra-selection", "line-selection", "headers", "digest", "format", "version", "trace"} {
		t.Run("profile-summary-sql-"+mode, func(t *testing.T) {
			s := scope
			switch mode {
			case "top":
				s.Profile.TopN = 101
			case "sample":
				s.Profile.SampleType = "cpu\n"
			case "line-selection":
				s.Selection = analysis.LineSelection{LineStart: 1, MaxLines: 1}
			case "headers":
				s.Headers = analysis.HTTPHeaderWindow{Limit: 1}
			case "digest":
				s.SourceProjectionDigest = artifact.Digest{1}
			case "format":
				s.SourceFormat = "wrong"
			case "version":
				s.DisplayVersion = "approved-pprof-summary/v2"
			case "trace":
				s.NativeType = artifact.GoTraceArtifact
			}
			raw, _ := json.Marshal(s)
			if mode == "extra-selection" {
				var obj map[string]any
				_ = json.Unmarshal(raw, &obj)
				obj["Profile"].(map[string]any)["labels"] = true
				raw, _ = json.Marshal(obj)
			}
			var valid bool
			if err := conn.QueryRow(ctx, "SELECT context_query_scope_source_valid($1::jsonb)", raw).Scan(&valid); err != nil || valid != (mode == "valid") {
				t.Fatal("closed summary selection", valid, err)
			}
		})
	}
	raw, _ := json.Marshal(scope)
	var units, batches int
	var tool, lane string
	var queryInput, oldInput bool
	if err := conn.QueryRow(ctx, `SELECT context_query_units($1::jsonb),context_query_read_batches($1::jsonb),context_query_begin_tool($1::jsonb),operation_audit_lane('get_profile_summary'),operation_audit_human_input_valid('get_profile_summary','context-query-input/v1'),operation_audit_human_input_valid('get_profile_summary','context-input/v1')`, raw).Scan(&units, &batches, &tool, &lane, &queryInput, &oldInput); err != nil || units != analysis.ProfileSummaryQueryUnits || batches != 1 || tool != "get_profile_summary" || lane != "normal" || !queryInput || oldInput {
		t.Fatal("summary accounting/audit", units, batches, tool, lane, queryInput, oldInput, err)
	}
}
