package integration

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
)

func logsQuerySQLScope(t *testing.T) []byte {
	t.Helper()
	var s query.ContextProjectionScope
	if err := json.Unmarshal(packetQuerySQLScope(t, true), &s); err != nil {
		t.Fatal(err)
	}
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.LogsArtifact, artifact.LogFormat, query.LogQueryDisplayVersion
	s.PacketQuery = query.PacketQueryWindow{}
	s.Logs = query.LogWindow{Limit: 100}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func qualifyLogsQuerySQLFunctions(t *testing.T, ctx context.Context, c *pgx.Conn) {
	t.Helper()
	body := logsQuerySQLScope(t)
	var good bool
	var tool, lane string
	var units, batches int
	if err := c.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb),context_query_begin_tool($1::jsonb),context_query_units($1::jsonb),context_query_read_batches($1::jsonb),operation_audit_lane('get_logs')`, body).Scan(&good, &tool, &units, &batches, &lane); err != nil || !good || tool != "get_logs" || units != 20 || batches != 2 || lane != "normal" {
		t.Fatal("logs closed source", good, tool, units, batches, lane, err)
	}
	for name, change := range map[string]func(map[string]any){
		"no-grant":          func(m map[string]any) { delete(m, "RawGrantID") },
		"metadata-kind":     func(m map[string]any) { m["NativeType"] = artifact.SyscallRecordsArtifact },
		"format":            func(m map[string]any) { m["SourceFormat"] = artifact.SyscallArgumentsFormat },
		"zero-page":         func(m map[string]any) { m["Logs"].(map[string]any)["Limit"] = 0 },
		"huge-page":         func(m map[string]any) { m["Logs"].(map[string]any)["Limit"] = 101 },
		"offset":            func(m map[string]any) { m["Logs"].(map[string]any)["Offset"] = 4096 },
		"unbound-cursor":    func(m map[string]any) { m["Logs"].(map[string]any)["Fragment"] = 1 },
		"other-selection":   func(m map[string]any) { m["PacketQuery"] = map[string]any{} },
		"projection-digest": func(m map[string]any) { m["SourceProjectionDigest"].([]any)[0] = 1 },
	} {
		t.Run("logs-sql-"+name, func(t *testing.T) {
			var m map[string]any
			if e := json.Unmarshal(body, &m); e != nil {
				t.Fatal(e)
			}
			change(m)
			b, _ := json.Marshal(m)
			if e := c.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, b).Scan(&good); e != nil || good {
				t.Fatal("bad logs source accepted", good, e)
			}
		})
	}
	qualifyRawSyscallQuerySQLFunctions(t, ctx, c)
}
