package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
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
	lookups        int
	conflict       bool
	initialRequest value.ContextQueryRequest
	replayCalls    map[string]value.ContextQueryRequest
	registrations  int
	registerErr    error
	registerHook   func()
}

func (f *packetQueryLedgerFixture) AdmitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) (ContextQueryAdmission, error) {
	f.initialRequest = r
	return f.projectionFixture.AdmitQuery(ctx, q, r, a)
}

// Like the real ledger, Permit cannot authorize a fresh audited Begin whose
// exact call has never been registered. Original admission/polls keep their
// existing fixture registration model.
func (f *packetQueryLedgerFixture) PermitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	if r.Call.Tool == q.Scope.BeginTool() && r.Call.ID != q.OperationID {
		if stored, ok := f.replayCalls[r.Call.ID]; !ok || stored != r {
			return value.ErrUnavailable
		}
	}
	return f.projectionFixture.PermitQuery(ctx, q, r, a)
}
func (f *packetQueryLedgerFixture) RegisterQueryReplayCall(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	if ctx.Err() != nil || !q.Equal(f.q) || !q.Current(a, f.now) || !r.Valid(f.now) || r.Call.Tool != q.Scope.BeginTool() || r.Call.ID == q.OperationID || r.Call.Principal != q.Scope.Principal || !q.InvocationKey.Valid() || r.Call.InputFormat != f.initialRequest.Call.InputFormat || r.Call.MACVersion != f.initialRequest.Call.MACVersion || r.Call.InputDigest != f.initialRequest.Call.InputDigest {
		return value.ErrUnavailable
	}
	if f.registerHook != nil {
		f.registerHook()
	}
	if f.registerErr != nil {
		return f.registerErr
	}
	if f.replayCalls == nil {
		f.replayCalls = map[string]value.ContextQueryRequest{}
	}
	if old, ok := f.replayCalls[r.Call.ID]; ok {
		if old != r {
			return value.ErrUnavailable
		}
		return nil
	}
	f.replayCalls[r.Call.ID] = r
	f.registrations++
	return nil
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
	if e != nil || !again.Pending() || again.Association().QueryID != id || !again.QueryDeadline().Equal(deadline) || again.Effect() != ContextQueryReplayed || compiler.calls != 1 || f.admissions != 1 || f.starts != 1 || f.observations != 1 || f.reads != 0 || f.polls != 0 || ledger.registrations != 1 {
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

func TestPacketQueryReplayRegistrationRefusesChangedMACAndRetainsOriginalBudget(t *testing.T) {
	for _, mode := range []string{"registered", "missing-facet", "registration-failed", "input-digest", "input-format", "mac-version", "cancel-after-register", "original-expired"} {
		t.Run(mode, func(t *testing.T) {
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
			f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.PacketQueryWorkerBytes, value.PacketQueryWorkerBytes
			ledger := &packetQueryLedgerFixture{projectionFixture: f}
			compiler := &packetQueryCompilerFixture{}
			f.s.Results.Ledger = ledger
			f.s.PacketRoutes = packetQueryRoute{s.Candidate()}
			f.s.PacketCompiler = compiler
			reads, _ := f.s.PacketQueries()
			first := f.invocation("pcap_query")
			first.input = ContextQueryInput{PacketQuery: r}
			d, e := reads.Begin(t.Context(), f, first, r)
			if e != nil {
				t.Fatal(e)
			}
			first.outcome = d
			original := f.q
			if e = d.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			if mode == "missing-facet" {
				f.s.Results.Ledger = struct {
					ContextQueryLedger
					ContextQueryInvocationLookup
				}{ledger, ledger}
				reads, _ = f.s.PacketQueries()
			}
			if mode == "registration-failed" {
				ledger.registerErr = value.ErrUnavailable
			}
			if mode == "original-expired" {
				f.refresh(f.q.Deadline.Add(time.Millisecond))
			}
			call, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel-after-register" {
				ledger.registerHook = cancel
			}
			replay := f.invocation("pcap_query")
			replay.input = ContextQueryInput{PacketQuery: r}
			switch mode {
			case "input-digest":
				replay.call.InputDigest[0] ^= 1
			case "input-format":
				replay.call.InputFormat = "other-input/v1"
			case "mac-version":
				replay.call.MACVersion = "other"
			}
			d, e = reads.Begin(call, f, replay, r)
			if mode == "registered" {
				if e != nil || d == nil || !d.Pending() || d.Association().QueryID != original.ID || d.Effect() != ContextQueryReplayed || ledger.registrations != 1 {
					t.Fatal("registered replay", e)
				}
				replay.outcome = d
				if e = d.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
			} else if e == nil || d != nil {
				t.Fatal("invalid repetition admitted", mode)
			}
			if !f.q.Equal(original) || f.admissions != 1 || f.starts != 1 || compiler.calls != 1 || f.polls != 0 || f.batches != 0 || f.reads != 0 || f.observations != 1 {
				t.Fatal("replay changed query/work/disclosure", mode)
			}
			if mode != "registered" && mode != "cancel-after-register" && ledger.registrations != 0 {
				t.Fatal("invalid replay registered", mode)
			}
		})
	}
}
