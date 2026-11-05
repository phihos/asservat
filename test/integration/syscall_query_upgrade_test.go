package integration

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"testing"
)

func rawSyscallQuerySQLScope(t *testing.T) []byte {
	t.Helper()
	var scope query.ContextProjectionScope
	if err := json.Unmarshal(packetQuerySQLScope(t, true), &scope); err != nil {
		t.Fatal(err)
	}
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.SyscallArgumentsArtifact, artifact.SyscallArgumentsFormat, query.SyscallQueryDisplayVersion
	scope.PacketQuery = query.PacketQueryWindow{}
	scope.Syscalls = query.SyscallWindow{View: query.SyscallQueryView, Limit: 100}
	body, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func qualifyRawSyscallQuerySQLFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	body := rawSyscallQuerySQLScope(t)
	var good bool
	var tool, lane string
	var units, batches int
	if err := conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb),context_query_begin_tool($1::jsonb),context_query_units($1::jsonb),context_query_read_batches($1::jsonb),operation_audit_lane('syscall_query')`, body).Scan(&good, &tool, &units, &batches, &lane); err != nil || !good || tool != "syscall_query" || units != 4 || batches != 2 || lane != "normal" {
		t.Fatal("raw syscall query SQL source", good, tool, units, batches, lane, err)
	}
	var original map[string]any
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"no-grant":        func(m map[string]any) { delete(m, "RawGrantID") },
		"bad-grant":       func(m map[string]any) { m["RawGrantID"] = "" },
		"metadata-source": func(m map[string]any) { m["NativeType"] = artifact.SyscallRecordsArtifact },
		"metadata-format": func(m map[string]any) { m["SourceFormat"] = artifact.SyscallRecordsFormat },
		"events-view":     func(m map[string]any) { m["Syscalls"].(map[string]any)["View"] = "events" },
		"packet-window":   func(m map[string]any) { m["PacketQuery"] = map[string]any{} },
		"trailing-name":   func(m map[string]any) { m["Syscalls"].(map[string]any)["Names"].([]any)[63] = "write" },
		"huge-page":       func(m map[string]any) { m["Syscalls"].(map[string]any)["Limit"] = 101 },
		"wrong-digest":    func(m map[string]any) { m["SourceProjectionDigest"].([]any)[0] = float64(1) },
	} {
		t.Run("raw-syscall-sql-"+name, func(t *testing.T) {
			var bad map[string]any
			if err := json.Unmarshal(body, &bad); err != nil {
				t.Fatal(err)
			}
			mutate(bad)
			encoded, _ := json.Marshal(bad)
			if err := conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, encoded).Scan(&good); err != nil || good {
				t.Fatal("invalid raw syscall scope accepted", good, err)
			}
		})
	}
	qualifyPacketQuerySQLFunctions(t, ctx, conn)
}
