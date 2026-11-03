package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

func qualifyProfileComparisonQueryFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	id, baseline := custodyID(), custodyID()
	scope := value.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: artifact.PprofArtifact, SourceFormat: artifact.PprofFormat, DisplayVersion: value.ProfileComparisonDisplayVersion, Profile: value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}, Comparison: value.ProfileComparisonWindow{Normalization: value.ProfileComparisonRate, Baseline: value.ProfileComparisonBaseline{CaseID: baseline, ArtifactID: baseline, CaptureID: baseline, ClusterID: baseline, NamespaceUID: "baseline-ns", WorkloadUID: "baseline-workload", PodUID: "baseline-pod", Version: artifact.Digest{2}}}}
	if !scope.Valid() {
		t.Fatal("comparison scope fixture invalid")
	}
	for _, mode := range []string{"valid", "none", "same-artifact", "same-artifact-case", "same-artifact-version", "baseline-case", "baseline-namespace", "baseline-control", "baseline-zero-uuid", "baseline-upper-uuid", "baseline-version", "normalization", "missing-window", "summary-display", "other-source", "headers", "extra-window", "extra-baseline", "version-length", "version-byte", "max-escaped"} {
		t.Run("profile-comparison-sql-"+mode, func(t *testing.T) {
			s := scope
			expect := mode == "valid" || mode == "none" || mode == "same-artifact" || mode == "max-escaped"
			switch mode {
			case "none":
				s.Comparison.Normalization = value.ProfileComparisonRaw
			case "same-artifact", "same-artifact-case", "same-artifact-version":
				s.Comparison.Baseline = value.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}
				if mode == "same-artifact-case" {
					s.Comparison.Baseline.CaseID = baseline
				}
				if mode == "same-artifact-version" {
					s.Comparison.Baseline.Version[0]++
				}
			case "baseline-case":
				s.Comparison.Baseline.CaseID = "invalid"
			case "baseline-namespace":
				s.Comparison.Baseline.NamespaceUID = ""
			case "baseline-control":
				s.Comparison.Baseline.PodUID = "pod\n"
			case "baseline-zero-uuid":
				s.Comparison.Baseline.CaseID = "00000000-0000-0000-0000-000000000000"
			case "baseline-upper-uuid":
				s.Comparison.Baseline.CaseID = "ABCDEFAB-1234-4567-8123-123456789abc"
			case "baseline-version":
				s.Comparison.Baseline.Version = artifact.Digest{}
			case "normalization":
				s.Comparison.Normalization = "rate"
			case "missing-window":
				s.Comparison = value.ProfileComparisonWindow{}
			case "summary-display":
				s.DisplayVersion = value.ProfileSummaryDisplayVersion
			case "other-source":
				s.NativeType = artifact.GoTraceArtifact
			case "headers":
				s.Headers = value.HTTPHeaderWindow{Limit: 1}
			case "max-escaped":
				s.Profile.SampleType = strings.Repeat("<", 64)
				s.Comparison.Baseline.NamespaceUID = strings.Repeat("<", 64)
				s.Comparison.Baseline.WorkloadUID = strings.Repeat(">", 64)
				s.Comparison.Baseline.PodUID = strings.Repeat("&", 64)
			}
			if mode != "extra-window" && mode != "extra-baseline" && mode != "version-length" && mode != "version-byte" && s.Valid() != expect {
				t.Fatal("Go typed validity fixture mismatch", mode)
			}
			raw, e := json.Marshal(s)
			if e != nil {
				t.Fatal(e)
			}
			if strings.HasPrefix(mode, "extra-") || strings.HasPrefix(mode, "version-") {
				var obj map[string]any
				if e = json.Unmarshal(raw, &obj); e != nil {
					t.Fatal(e)
				}
				window := obj["Comparison"].(map[string]any)
				child := window["Baseline"].(map[string]any)
				switch mode {
				case "extra-window":
					window["Extra"] = true
				case "extra-baseline":
					child["Principal"] = obj["Principal"]
				case "version-length":
					child["Version"] = []int{1}
				case "version-byte":
					v := make([]int, 32)
					v[0] = 256
					child["Version"] = v
				}
				raw, e = json.Marshal(obj)
				if e != nil {
					t.Fatal(e)
				}
			}
			var accepted bool
			if e = conn.QueryRow(ctx, "SELECT context_query_scope_source_valid($1::jsonb)", raw).Scan(&accepted); e != nil || accepted != expect {
				t.Fatal("comparison Go/SQL closed scope parity", mode, accepted, e)
			}
		})
	}
	raw, _ := json.Marshal(scope)
	var units, batches int
	var tool, lane string
	var input, wrong bool
	if e := conn.QueryRow(ctx, `SELECT context_query_units($1::jsonb),context_query_read_batches($1::jsonb),context_query_begin_tool($1::jsonb),operation_audit_lane('compare_profiles'),operation_audit_human_input_valid('compare_profiles','context-query-input/v1'),operation_audit_human_input_valid('compare_profiles','context-input/v1')`, raw).Scan(&units, &batches, &tool, &lane, &input, &wrong); e != nil || units != 20 || batches != 1 || tool != "compare_profiles" || lane != "normal" || !input || wrong {
		t.Fatal("comparison accounting/audit identity", units, batches, tool, lane, input, wrong, e)
	}
}
