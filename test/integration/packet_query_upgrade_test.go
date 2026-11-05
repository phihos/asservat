package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"context"
	"encoding/json"
	"strings"
	"testing"

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
		for _, mutate := range []func(*query.ContextProjectionScope){
			func(s *query.ContextProjectionScope) { s.PacketQuery.Fields[2] = query.PacketWireLength },
			func(s *query.ContextProjectionScope) {
				s.PacketQuery.Instructions[0] = artifact.FilterInstruction{Code: 6, K: 1}
			},
			func(s *query.ContextProjectionScope) { s.PacketQuery.MaxPackets = 101 },
			func(s *query.ContextProjectionScope) { s.PacketQuery.ProgramDigest[0] = 1 },
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
