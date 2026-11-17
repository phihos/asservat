package postgres

import (
	"bytes"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
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
	a.Grant = query.ContextQueryGrant{ParentID: comparisonPlanID, ArtifactRef: comparisonPlanID}
	q, err = query.NewContextQuery(q.ID, q.OperationID, q.WorkerID, a, q.Plan, q.CreatedAt, query.ContextQueryInvocationKey{Key: "original-packet-query", RequestDigest: artifact.Digest{23}})
	if err != nil || !q.Current(a, q.CreatedAt) {
		t.Fatal("packet query fixture", err)
	}
	return q, a
}

func TestPacketQueryLedgerRowPinsCallerKeyAndGrant(t *testing.T) {
	q, a := packetQueryLedgerValue(t)
	changedAuthority := a
	changedAuthority.Grant.ArtifactRef = "10000000-0000-4000-8000-000000000099"
	if q.Current(changedAuthority, q.CreatedAt) {
		t.Fatal("current authority substituted original child")
	}
	row := custodydb.ContextQuery{ID: id(q.ID), RootID: id(q.Scope.RootID), AllocationID: id(q.Plan.AllocationID), AccountID: id(q.Plan.AccountID), PrincipalKey: principalKey(q.Scope.Principal), Actor: comparisonJSON(t, q.Scope.Principal), Query: comparisonJSON(t, q), OperationID: id(q.OperationID), WorkerID: id(q.WorkerID), CreatedAt: ts(q.CreatedAt), Deadline: ts(q.Deadline), CleanupUntil: ts(q.CleanupUntil), RetireBy: ts(q.Plan.RetireBy), IssuerEpoch: id(q.Plan.InstallationID), InvocationKey: nullableString(q.InvocationKey.Key), RequestDigest: queryInvocationDigest(q)}
	if got, err := queryFromRow(row); err != nil || !got.Equal(q) {
		t.Fatal("original caller-key row refused", err)
	}
	for _, mutate := range []func(*custodydb.ContextQuery){
		func(r *custodydb.ContextQuery) { r.InvocationKey = nullableString("") },
		func(r *custodydb.ContextQuery) { r.InvocationKey = nullableString("changed-key") },
		func(r *custodydb.ContextQuery) { r.RequestDigest = bytes.Repeat([]byte{7}, 32) },
		func(r *custodydb.ContextQuery) {
			other := q
			other.Grant.ArtifactRef = ""
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
