package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
)

func packetQuerySQLScope(t *testing.T, raw bool) []byte {
	t.Helper()
	var s query.ContextProjectionScope
	if err := json.Unmarshal(packetSummarySQLScope(t, raw), &s); err != nil {
		t.Fatal(err)
	}
	s.DisplayVersion = query.PacketQueryDisplayVersion
	selection := query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketIndex, query.PacketCapturedLength}, MaxPackets: 100, MaxScanBytes: 8 << 20}
	window, err := selection.Window()
	if err != nil {
		t.Fatal(err)
	}
	s.PacketQuery = window
	if raw {
		s.RawGrantID = custodyID()
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A nonempty verified BPF program reaches both SQL digest checks. Empty
// programs return earlier and cannot qualify this producer/consumer boundary.
func packetQueryNonemptyProgram() query.PacketQueryProgram {
	instructions := []artifact.FilterInstruction{{Code: 6, K: 0xffffffff}}
	return query.PacketQueryProgram{Instructions: instructions, CompilerDigest: query.PacketQueryCompilerDigest(), ProgramDigest: query.PacketQueryProgramDigest(instructions)}
}

func TestPacketQueryNonemptyProgramWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run the owned custody fixture")
	}
	var f fixture
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &f) != nil || f.Postgres == "" {
		t.Fatal("fixture unavailable", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	qualifyPacketQuerySQLFunctions(t, ctx, conn)
}

func qualifyPacketQuerySQLFunctions(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	for _, raw := range []bool{false, true} {
		b := packetQuerySQLScope(t, raw)
		var good bool
		var tool, lane string
		var units, batches int
		if err := conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb),context_query_begin_tool($1::jsonb),context_query_units($1::jsonb),context_query_read_batches($1::jsonb),operation_audit_lane('pcap_query')`, b).Scan(&good, &tool, &units, &batches, &lane); err != nil || !good || tool != "pcap_query" || units != 4 || batches != 2 || lane != "normal" {
			t.Fatal("closed packet query SQL source", raw, good, tool, units, batches, lane, err)
		}
		var scope query.ContextProjectionScope
		if err := json.Unmarshal(b, &scope); err != nil {
			t.Fatal(err)
		}
		compiled := scope.PacketQuery.Selection()
		compiled.Program = packetQueryNonemptyProgram()
		window, err := compiled.Window()
		if err != nil {
			t.Fatal("valid nonempty program", err)
		}
		scope.PacketQuery = window
		encoded, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, encoded).Scan(&good); err != nil || !good {
			t.Fatal("nonempty compiled packet query SQL source", raw, good, err)
		}
		for _, mutate := range []func(*query.ContextProjectionScope){
			func(s *query.ContextProjectionScope) { s.PacketQuery.Fields[2] = query.PacketWireLength },
			func(s *query.ContextProjectionScope) {
				s.PacketQuery.Instructions[0] = artifact.FilterInstruction{Code: 6, K: 1}
			},
			func(s *query.ContextProjectionScope) { s.PacketQuery.MaxPackets = 101 },
			func(s *query.ContextProjectionScope) { s.PacketQuery.ProgramDigest[0] ^= 1 },
			func(s *query.ContextProjectionScope) { s.PacketQuery.CompilerDigest[0] ^= 1 },
			func(s *query.ContextProjectionScope) { s.SourceFormat = "arbitrary" },
		} {
			bad := scope
			mutate(&bad)
			encoded, _ := json.Marshal(bad)
			if err := conn.QueryRow(ctx, `SELECT context_query_scope_source_valid($1::jsonb)`, encoded).Scan(&good); err != nil || good {
				t.Fatal("invalid query source accepted", err)
			}
		}
	}
	qualifyPacketSummaryQueryFunctions(t, ctx, conn)
	qualifyPacketSummaryQueryFunctions(t, ctx, conn, true)
}

// Restoring a dropped function gives it a new OID and no runtime ACL. Reapply
// ONLY the exact original compiled predicate grants after fixture-only rollback.
func restorePacketQueryFixturePredicate(t *testing.T, ctx context.Context, f *queryLedgerFixture) {
	t.Helper()
	for _, purpose := range []string{"hub-runtime", "key-acquisition"} {
		pool := f.base.roles[purpose]
		if pool == nil {
			t.Fatal("missing original compiled role", purpose)
		}
		statements, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, pool.Config().ConnConfig.User)
		if !ok {
			t.Fatal("unknown role", purpose)
		}
		found := false
		for _, statement := range statements {
			if strings.HasPrefix(statement, "GRANT EXECUTE ON FUNCTION public.context_packet_query_grant_current(") {
				if _, err := f.base.admin.Exec(ctx, statement); err != nil {
					t.Fatal("restore original predicate ACL", err)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("compiled predicate grant missing", purpose)
		}
	}
}

// Historical fixture preparation can consume pg_attribute slots by dropping
// and re-adding old columns. Ignore ONLY those numeric slots for this separate
// preparation check. Array order and every other logical schema value remain
// exact. The actual139roundtrip still compares its full snapshot byte-for-byte.
func packetQueryPreparationShape(before, after string) ([]string, error) {
	var a, b map[string]any
	if json.Unmarshal([]byte(before), &a) != nil || json.Unmarshal([]byte(after), &b) != nil {
		return nil, fmt.Errorf("invalid preparation schema snapshots")
	}
	first, ok := a["columns"].([]any)
	last, okLast := b["columns"].([]any)
	if !ok || !okLast || len(first) == 0 || len(first) != len(last) {
		return nil, fmt.Errorf("preparation changed visible column count")
	}
	var drift []string
	for i, c := range first {
		x, ok := c.(map[string]any)
		y, okY := last[i].(map[string]any)
		if !ok || !okY {
			return nil, fmt.Errorf("invalid column snapshot")
		}
		old, ok := x["ordinal_position"].(float64)
		current, okNow := y["ordinal_position"].(float64)
		if !ok || !okNow || old < 1 || current < 1 || old != float64(int(old)) || current != float64(int(current)) {
			return nil, fmt.Errorf("invalid column ordinal")
		}
		if old != current {
			drift = append(drift, fmt.Sprintf("%s.%s:%d->%d", x["table_name"], x["column_name"], int(old), int(current)))
		}
		delete(x, "ordinal_position")
		delete(y, "ordinal_position")
		if !reflect.DeepEqual(x, y) {
			return nil, fmt.Errorf("preparation changed column/order at position%d", i)
		}
	}
	if !reflect.DeepEqual(a, b) {
		return nil, fmt.Errorf("preparation changed constraints/indexes or other schema values")
	}
	return drift, nil
}

func TestPacketQueryPreparationShapePreservesLogicalSchema(t *testing.T) {
	before := map[string]any{"columns": []any{map[string]any{"table_name": "context_query", "column_name": "id", "ordinal_position": 1, "data_type": "uuid", "is_nullable": "NO", "column_default": nil}, map[string]any{"table_name": "context_query", "column_name": "baseline_allocation_id", "ordinal_position": 23, "data_type": "uuid", "is_nullable": "YES", "column_default": nil}}, "constraints": []any{"context_query:oldcheck", "context_query_key_binding:typedbound"}, "indexes": []any{"CREATE UNIQUE INDEX original ON context_query(id)"}}
	baseline, _ := json.Marshal(before)
	prepared := func() map[string]any {
		var out map[string]any
		if json.Unmarshal(baseline, &out) != nil {
			t.Fatal("fixture")
		}
		out["columns"].([]any)[1].(map[string]any)["ordinal_position"] = float64(24)
		return out
	}
	b, _ := json.Marshal(prepared())
	drift, err := packetQueryPreparationShape(string(baseline), string(b))
	if err != nil || !reflect.DeepEqual(drift, []string{"context_query.baseline_allocation_id:23->24"}) {
		t.Fatal("physicalslotonlychange", drift, err)
	}
	for _, mode := range []string{"name", "order", "type", "nullable", "default", "constraint", "index"} {
		t.Run(mode, func(t *testing.T) {
			bad := prepared()
			cols := bad["columns"].([]any)
			c := cols[1].(map[string]any)
			switch mode {
			case "name":
				c["column_name"] = "replacement"
			case "order":
				cols[0], cols[1] = cols[1], cols[0]
			case "type":
				c["data_type"] = "text"
			case "nullable":
				c["is_nullable"] = "NO"
			case "default":
				c["column_default"] = "generated"
			case "constraint":
				bad["constraints"] = []any{"weaker"}
			case "index":
				bad["indexes"] = []any{"nonunique"}
			}
			b, _ := json.Marshal(bad)
			if _, err := packetQueryPreparationShape(string(baseline), string(b)); err == nil {
				t.Fatal("logical schema delta hidden", mode)
			}
		})
	}
}
