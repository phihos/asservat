package postgres

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/migrations"
)

func packetQueryLedgerValue(t *testing.T) (query.ContextQuery, query.ContextProjectionAuthority) {
	compound, a, _, _ := comparisonLedgerFixture(t)
	q, a := projectionQuerySource(compound, a, false)
	a.Scope.NativeType, a.Scope.SourceFormat, a.Scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, query.PacketQueryDisplayVersion
	a.Scope.Profile = query.ProfileSummarySelection{}
	a.Scope.RawGrantID = comparisonPlanID
	selection := query.PacketQuerySelection{Fields: []query.PacketQueryField{query.PacketCapturedLength}, MaxPackets: 100, MaxScanBytes: 8 << 20}
	window, err := selection.Window()
	if err != nil {
		t.Fatal(err)
	}
	a.Scope.PacketQuery = window
	a.Grant = query.ContextQueryGrant{ParentID: comparisonPlanID, ChildID: comparisonPlanID}
	q, err = query.NewContextQuery(q.ID, q.OperationID, q.WorkerID, a, q.Plan, q.CreatedAt, query.ContextQueryInvocationKey{Key: "original-packet-query", RequestDigest: artifact.Digest{23}})
	if err != nil || !q.Current(a, q.CreatedAt) {
		t.Fatal("packet query fixture", err)
	}
	return q, a
}

func TestPacketQueryLedgerRowPinsCallerKeyAndGrant(t *testing.T) {
	q, a := packetQueryLedgerValue(t)
	changedAuthority := a
	changedAuthority.Grant.ChildID = "10000000-0000-4000-8000-000000000099"
	if q.Current(changedAuthority, q.CreatedAt) {
		t.Fatal("current authority substituted original child")
	}
	row := custodydb.ContextQuery{ID: id(q.ID), RootID: id(q.Scope.RootID), AllocationID: id(q.Plan.AllocationID), AccountID: id(q.Plan.AccountID), PrincipalKey: principalKey(q.Scope.Principal), Actor: comparisonJSON(t, q.Scope.Principal), Query: comparisonJSON(t, q), OperationID: id(q.OperationID), WorkerID: id(q.WorkerID), CreatedAt: ts(q.CreatedAt), Deadline: ts(q.Deadline), CleanupUntil: ts(q.CleanupUntil), RetireBy: ts(q.Plan.RetireBy), IssuerEpoch: id(q.RecoveryIssuerEpoch), InvocationKey: nullableString(q.InvocationKey.Key), RequestDigest: queryInvocationDigest(q)}
	if got, err := queryFromRow(row); err != nil || !got.Equal(q) {
		t.Fatal("original caller-key row refused", err)
	}
	for _, mutate := range []func(*custodydb.ContextQuery){
		func(r *custodydb.ContextQuery) { r.InvocationKey = nullableString("") },
		func(r *custodydb.ContextQuery) { r.InvocationKey = nullableString("changed-key") },
		func(r *custodydb.ContextQuery) { r.RequestDigest = bytes.Repeat([]byte{7}, 32) },
		func(r *custodydb.ContextQuery) {
			other := q
			other.Grant.ChildID = ""
			r.Query = comparisonJSON(t, other)
		},
	} {
		bad := row
		mutate(&bad)
		if _, err := queryFromRow(bad); err == nil {
			t.Fatal("changed immutable association accepted")
		}
	}
}

func TestPacketQueryMigrationRestoresEveryPreviousFunction(t *testing.T) {
	files, err := fs.Glob(migrations.Files(), "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"context_query_scope_source_valid", "context_query_begin_tool", "context_query_read_batches", "context_query_units", "guard_context_query", "guard_context_query_account", "guard_context_query_child", "operation_audit_lane", "operation_audit_human_input_valid", "guard_operation_audit", "context_query_intent_current", "context_query_outcome_closed"}
	old := map[string]string{}
	oldKeyConstraint := ""
	for _, file := range files {
		if file >= "00139_saved_packet_query.sql" {
			continue
		}
		b, err := fs.ReadFile(migrations.Files(), file)
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(b), "-- +goose Down")
		if constraint := regexp.MustCompile(`(?s)ALTER TABLE context_query_key_binding ADD CONSTRAINT context_query_key_binding_binding_check CHECK.*?;`).FindString(up); constraint != "" {
			oldKeyConstraint = constraint
		}
		for _, n := range names {
			re := regexp.MustCompile(`(?s)CREATE (?:OR REPLACE )?FUNCTION ` + regexp.QuoteMeta(n) + `\(.*?\$\$;`)
			if def := re.FindString(up); def != "" {
				old[n] = strings.Replace(def, "CREATE FUNCTION ", "CREATE OR REPLACE FUNCTION ", 1)
			}
		}
	}
	b, err := fs.ReadFile(migrations.Files(), "00139_saved_packet_query.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("missing down")
	}
	for _, n := range names {
		if old[n] == "" || !strings.Contains(down, old[n]) {
			t.Fatal("Down did not restore exact prior function", n)
		}
	}
	if oldKeyConstraint == "" || !strings.Contains(down, oldKeyConstraint) {
		t.Fatal("Down did not restore exact previous key-binding constraint")
	}
	if !strings.Contains(down, "packet query history cannot be downgraded") || !strings.Contains(down, "operation='pcap_query'") || !strings.Contains(down, "raw_query->'Operations' ? 'pcap_query'") {
		t.Fatal("retained query/grant/use fence missing")
	}
	if strings.Contains(up, "CREATE TABLE") || strings.Contains(up, "GRANT SELECT") {
		t.Fatal("unexpected new journal or broad grant read")
	}
}

func TestPacketQueryKeyBindingSizeIsPurposeBounded(t *testing.T) {
	_, a := packetQueryLedgerValue(t)
	program := make([]artifact.FilterInstruction, query.PacketQueryMaxInstructions)
	for i := range program {
		program[i] = artifact.FilterInstruction{Code: 6, K: 0xffffffff}
	}
	selection := a.Scope.PacketQuery.Selection()
	selection.Program = query.PacketQueryProgram{Instructions: program, CompilerDigest: query.PacketQueryCompilerDigest(), ProgramDigest: query.PacketQueryProgramDigest(program)}
	window, err := selection.Window()
	if err != nil {
		t.Fatal(err)
	}
	a.Scope.PacketQuery = window
	if !a.Scope.Valid() {
		t.Fatal("maximum program scope invalid")
	}
	binding := query.ContextProjectionKeyBinding{Authority: a}
	b := comparisonJSON(t, binding)
	if projectionKeyBindingBytes(binding) != 48<<10 || len(b) > projectionKeyBindingBytes(binding) {
		t.Fatal("packet query scoped key bound", len(b), projectionKeyBindingBytes(binding))
	}
	old := binding
	old.Authority.Scope.DisplayVersion = query.RawPacketSummaryDisplayVersion
	old.Authority.Scope.PacketQuery = query.PacketQueryWindow{}
	old.Authority.Scope.RawGrantID = ""
	if projectionKeyBindingBytes(old) != 16<<10 {
		t.Fatal("fixed summary key bound changed")
	}
	t.Logf("maximum256instruction query authority in key child=%dB, with distinct finite48KiB packet-query ceiling; existing summary16KiB unchanged", len(b))
}
