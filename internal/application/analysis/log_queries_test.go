package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
)

type logRouteFixture struct {
	candidate value.ContextProjectionCandidate
}

func (r logRouteFixture) ResolveLogProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.candidate, nil
}
func rawLogAdmissionFixture(t *testing.T) (*projectionFixture, *packetQueryLedgerFixture, value.RawLogQueryRequest) {
	f := newProjectionFixture(t)
	f.ready = false
	s := &f.a.Scope
	selection, e := value.NormalizeLogSelection(s.CaseID, s.ArtifactID, "", 10)
	if e != nil {
		t.Fatal(e)
	}
	source, ok := value.LookupProjectionSourceFor(artifact.LogsArtifact, value.LogQueryDisplayVersion)
	if !ok {
		t.Fatal("raw source unregistered")
	}
	s.NativeType, s.SourceFormat, s.SourceProjectionDigest, s.DisplayVersion = source.NativeType, source.Format, source.ProjectionDigest, source.DisplayVersion
	s.Selection, s.Logs = value.LineSelection{}, selection.LogWindow
	s.RawGrantID = f.next()
	f.a.Grant = value.ContextQueryGrant{ParentID: s.RawGrantID, ChildID: f.next()}
	f.i.Scopes = append(f.i.Scopes, "evidence:raw")
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.LogQueryWorkerBytes, value.LogQueryWorkerBytes
	candidate := s.Candidate()
	candidate.Logs = value.LogWindow{}
	candidate.RawGrantID = ""
	f.s.LogRoutes = logRouteFixture{candidate}
	ledger := &packetQueryLedgerFixture{projectionFixture: f}
	f.s.Results.Ledger = ledger
	r := value.RawLogQueryRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID, GrantID: s.RawGrantID, IdempotencyKey: "raw-syscall-original", Selection: s.Logs}
	return f, ledger, r
}
func TestRawLogBeginPinsInvocationBeforeAdmissionAndReplay(t *testing.T) {
	f, ledger, r := rawLogAdmissionFixture(t)
	service, ok := f.s.RawLogQueries()
	if !ok {
		t.Fatal("not composed")
	}
	invoke := f.invocation("get_logs")
	invoke.input = ContextQueryInput{RawLogs: r}
	d, e := service.Begin(t.Context(), f, invoke, r)
	if e != nil {
		t.Fatalf("raw query admission: %v", e)
	}
	if !d.Pending() || f.q.Scope.QueryUnits() != value.LogQueryUnits || f.q.Scope.ReadBatches() != 2 || !f.q.InvocationKey.Valid() || f.q.Grant != f.a.Grant {
		t.Fatal("query funding or immutable grant/key missing")
	}
	id, deadline := d.Association().QueryID, d.QueryDeadline()
	invoke.outcome = d
	if e = d.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	replay := f.invocation("get_logs")
	replay.input = ContextQueryInput{RawLogs: r}
	again, e := service.Begin(t.Context(), f, replay, r)
	if e != nil || !again.Pending() || again.Effect() != ContextQueryReplayed || again.Association().QueryID != id || !again.QueryDeadline().Equal(deadline) || f.starts != 1 || f.admissions != 1 || f.reads != 0 || f.observations != 1 || ledger.lookups != 2 || ledger.registrations != 1 {
		t.Fatal("replay caused successor or effects", e)
	}
	replay.outcome = again
	if e = again.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.Selection.Limit--
	bad := f.invocation("get_logs")
	bad.input = ContextQueryInput{RawLogs: changed}
	if d, e = service.Begin(t.Context(), f, bad, changed); e == nil || d != nil || f.starts != 1 || f.admissions != 1 {
		t.Fatal("changed key accepted", e)
	}
	if RawLogQueryRequestDigest(r) == PacketQueryRequestDigest(value.PacketQueryRequest{IdempotencyKey: r.IdempotencyKey}) {
		t.Fatal("request digest not domain separated")
	}
}

type rawLogApprovalProofFailure struct{}

func (rawLogApprovalProofFailure) Error() string                     { return "raw logs approval required" }
func (rawLogApprovalProofFailure) RawLogQueryApprovalRequired() bool { return true }
func TestRawLogMissingApprovalRemainsActionableBeforeAnyEffect(t *testing.T) {
	f, _, r := rawLogAdmissionFixture(t)
	r.GrantID = ""
	f.a.Scope.RawGrantID = ""
	f.a.Grant = value.ContextQueryGrant{}
	f.authorityErr = rawLogApprovalProofFailure{}
	service, _ := f.s.RawLogQueries()
	inv := f.invocation("get_logs")
	inv.input = ContextQueryInput{RawLogs: r}
	d, err := service.Begin(t.Context(), f, inv, r)
	if d != nil || !RawLogQueryApprovalRequiredBeforeAdmission(err) || f.starts != 0 || f.admissions != 0 || f.reads != 0 {
		t.Fatal("missing approval became effect or opaque failure", err)
	}
}
