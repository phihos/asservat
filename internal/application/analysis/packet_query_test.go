package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
)

type packetQueryCompilerFixture struct {
	calls int
	err   error
}

func (c *packetQueryCompilerFixture) CompilePacketQueryFilter(context.Context, string) (value.PacketQueryProgram, error) {
	c.calls++
	return value.PacketQueryProgram{}, c.err
}

type packetQueryRoute struct {
	candidate value.ContextProjectionCandidate
}

func (r packetQueryRoute) ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.candidate, nil
}
func (r packetQueryRoute) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.candidate, nil
}

type packetQueryLedgerFixture struct {
	*projectionFixture
	lookups  int
	conflict bool
}

func (f *packetQueryLedgerFixture) LookupQueryInvocation(_ context.Context, _ identity.Principal, key string, digest artifact.Digest) (value.ContextQuery, bool, error) {
	f.lookups++
	if f.q.ID == "" {
		return value.ContextQuery{}, false, nil
	}
	if f.conflict || f.q.InvocationKey.Key != key || f.q.InvocationKey.RequestDigest != digest {
		return value.ContextQuery{}, false, value.ErrQueryConflict
	}
	return f.q, true, nil
}
func TestPacketQueryOriginalKeyReplayNeverCompilesOrStartsAgain(t *testing.T) {
	f := newProjectionFixture(t)
	f.ready = false
	r := value.PacketQueryRequest{CaseID: f.a.Scope.CaseID, ArtifactID: f.a.Scope.ArtifactID, IdempotencyKey: "original", Fields: []value.PacketQueryField{value.PacketIndex}, MaxPackets: 10, MaxScanBytes: 1000}
	s := &f.a.Scope
	s.NativeType = artifact.PCAPNGArtifact
	s.SourceFormat = artifact.PCAPNGFormat
	s.DisplayVersion = value.PacketQueryDisplayVersion
	s.SourceProjectionDigest = artifact.Digest{}
	s.Selection = value.LineSelection{}
	s.PacketQuery, _ = r.Selection(value.PacketQueryProgram{}).Window()
	f.p.Profile.Worker.MemoryBytes = value.PacketQueryWorkerBytes
	f.p.Profile.Worker.WorkerTransientBytes = value.PacketQueryWorkerBytes
	ledger := &packetQueryLedgerFixture{projectionFixture: f}
	compiler := &packetQueryCompilerFixture{}
	f.s.Results.Ledger = ledger
	f.s.PacketRoutes = packetQueryRoute{s.Candidate()}
	f.s.PacketCompiler = compiler
	reads, enabled := f.s.PacketQueries()
	if !enabled {
		t.Fatal("querydisabled")
	}
	inv := f.invocation("pcap_query")
	inv.input = ContextQueryInput{PacketQuery: r}
	d, e := reads.Begin(t.Context(), f, inv, r)
	if e != nil {
		t.Fatalf("initial %v stage=%#v calls auth=%d admissions=%d", e, e, f.authorityReads, f.admissions)
	}
	id := d.Association().QueryID
	deadline := d.QueryDeadline()
	inv.outcome = d
	if f.q.Scope.QueryUnits() != 4 || f.q.Scope.ReadBatches() != 2 || f.starts != 1 || f.reads != 0 {
		t.Fatal("queryfunding", f.q.Scope.QueryUnits())
	}
	if e = d.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	replay := f.invocation("pcap_query")
	replay.input = ContextQueryInput{PacketQuery: r}
	again, e := reads.Begin(t.Context(), f, replay, r)
	if e != nil || !again.Pending() || again.Association().QueryID != id || !again.QueryDeadline().Equal(deadline) || again.Effect() != ContextQueryReplayed || compiler.calls != 1 || f.admissions != 1 || f.starts != 1 || f.observations != 1 || f.reads != 0 || f.polls != 0 {
		t.Fatal("replaycausedwork", e, compiler.calls, f.admissions, f.starts, f.observations)
	}
	replay.outcome = again
	if e = again.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.MaxPackets = 2
	bad := f.invocation("pcap_query")
	bad.input = ContextQueryInput{PacketQuery: changed}
	if d, e := reads.Begin(t.Context(), f, bad, changed); e == nil || d != nil || compiler.calls != 1 || f.admissions != 1 {
		t.Fatal("changedkeyreplayed", e)
	}
}
