package integration

import (
	"context"
	"encoding/json"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
)

func processesQuerySQLScope(t *testing.T) []byte {
	t.Helper()
	var s query.ContextProjectionScope
	if err := json.Unmarshal(packetQuerySQLScope(t, false), &s); err != nil {
		t.Fatal(err)
	}
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.ProcessesArtifact, artifact.ProcessFormat, query.TargetDiscoveryDisplayVersion
	s.PacketQuery = query.PacketQueryWindow{}
	s.RawGrantID = ""
	s.Discovery = query.TargetDiscoveryWindow{Section: "processes", Limit: 20}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func qualifyProcessesQuerySQLFunctions(t *testing.T, ctx context.Context, c *pgx.Conn) {
	t.Helper()
	body := processesQuerySQLScope(t)
	var good, input bool
	var tool, lane string
	var units, batches int
	if err := c.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb),context_query_begin_tool($1::jsonb),context_query_units($1::jsonb),context_query_read_batches($1::jsonb),operation_audit_lane('get_target_discovery'),operation_audit_human_input_valid('get_target_discovery','context-query-input/v1')`, body).Scan(&good, &tool, &units, &batches, &lane, &input); err != nil || !good || tool != "get_target_discovery" || units != 2 || batches != 1 || lane != "normal" || !input {
		t.Fatal("processes exact SQL source", good, tool, units, batches, lane, input, err)
	}
	for name, change := range map[string]func(map[string]any){
		"wrong-type":        func(m map[string]any) { m["NativeType"] = artifact.PodStatusArtifact },
		"wrong-format":      func(m map[string]any) { m["SourceFormat"] = artifact.ContextFormat },
		"wrong-display":     func(m map[string]any) { m["DisplayVersion"] = query.ContextDisplayVersion },
		"no-window":         func(m map[string]any) { delete(m, "Discovery") },
		"wrong-section":     func(m map[string]any) { m["Discovery"].(map[string]any)["Section"] = "memory" },
		"zero-page":         func(m map[string]any) { m["Discovery"].(map[string]any)["Limit"] = 0 },
		"huge-page":         func(m map[string]any) { m["Discovery"].(map[string]any)["Limit"] = 101 },
		"start-over-native": func(m map[string]any) { m["Discovery"].(map[string]any)["Start"] = 257 },
		"unbound-cursor":    func(m map[string]any) { m["Discovery"].(map[string]any)["Start"] = 1 },
		"summary-cursor": func(m map[string]any) {
			w := m["Discovery"].(map[string]any)
			w["Section"] = "summary"
			w["Start"] = 1
			w["Binding"] = "0123456789abcdef0123456789abcdef"
		},
		"other-selection":   func(m map[string]any) { m["PacketQuery"] = map[string]any{} },
		"raw-grant":         func(m map[string]any) { m["RawGrantID"] = custodyID() },
		"projection-digest": func(m map[string]any) { m["SourceProjectionDigest"].([]any)[0] = 1 },
	} {
		t.Run("processes-sql-"+name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			change(m)
			b, _ := json.Marshal(m)
			if err := c.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, b).Scan(&good); err != nil || good {
				t.Fatal("bad processes scope accepted", good, err)
			}
		})
	}
	for _, w := range []query.TargetDiscoveryWindow{{Section: "summary", Limit: 1}, {Section: "processes", Start: 1, Limit: 100, Binding: "0123456789abcdef0123456789abcdef"}} {
		var s query.ContextProjectionScope
		_ = json.Unmarshal(body, &s)
		s.Discovery = w
		b, _ := json.Marshal(s)
		if err := c.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, b).Scan(&good); err != nil || !good {
			t.Fatal("valid processes window refused", err)
		}
	}
	qualifyLogsQuerySQLFunctions(t, ctx, c)
}
