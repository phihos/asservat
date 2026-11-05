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

func packetSummarySQLScope(t *testing.T) []byte {
	t.Helper()
	id := custodyID()
	s := analysis.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, NativeType: artifact.PCAPNGArtifact, SourceFormat: artifact.PCAPNGFormat, DisplayVersion: analysis.PacketSummaryDisplayVersion, Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "reader", ClientID: "fixture", Kind: identity.Human}}
	if !s.Valid() {
		t.Fatal("invalid packet summary fixture scope")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Migration source/tool/accounting parity only; real publication and role
// consumption are exercised separately through the shared lifecycle fixture.
func qualifyPacketSummaryQueryFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	raw := packetSummarySQLScope(t)
	for _, mode := range []string{"valid", "raw", "format", "display", "digest", "line", "headers", "profile", "syscalls", "comparison", "null-selection", "missing-selection", "extra-selection"} {
		t.Run("packet-summary-sql-"+mode, func(t *testing.T) {
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "raw":
				obj["NativeType"] = artifact.RawPCAPNGArtifact
			case "format":
				obj["SourceFormat"] = "wrong"
			case "display":
				obj["DisplayVersion"] = "approved-pcap-summary/v2"
			case "digest":
				obj["SourceProjectionDigest"] = []int{1}
			case "line":
				obj["Selection"] = map[string]int{"LineStart": 1, "MaxLines": 1}
			case "headers":
				obj["Headers"] = map[string]int{"Limit": 1}
			case "profile":
				obj["Profile"] = map[string]any{"SampleType": "cpu", "TopN": 1}
			case "syscalls":
				obj["Syscalls"] = map[string]any{}
			case "comparison":
				obj["Comparison"] = map[string]any{}
			case "null-selection":
				obj["Selection"] = nil
			case "missing-selection":
				delete(obj, "Selection")
			case "extra-selection":
				obj["Selection"].(map[string]any)["filter"] = "tcp"
			}
			b, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			var valid bool
			if err := conn.QueryRow(ctx, "SELECT context_query_scope_source_valid($1::jsonb)", b).Scan(&valid); err != nil || valid != (mode == "valid") {
				t.Fatal("closed packet summary selection", valid, err)
			}
		})
	}
	var units, batches int
	var tool, lane string
	var queryInput, oldInput bool
	if err := conn.QueryRow(ctx, `SELECT context_query_units($1::jsonb),context_query_read_batches($1::jsonb),context_query_begin_tool($1::jsonb),operation_audit_lane('get_pcap_summary'),operation_audit_human_input_valid('get_pcap_summary','context-query-input/v1'),operation_audit_human_input_valid('get_pcap_summary','context-input/v1')`, raw).Scan(&units, &batches, &tool, &lane, &queryInput, &oldInput); err != nil || units != analysis.PacketSummaryQueryUnits || batches != 1 || tool != "get_pcap_summary" || lane != "normal" || !queryInput || oldInput {
		t.Fatal("packet accounting/audit", units, batches, tool, lane, queryInput, oldInput, err)
	}
}
