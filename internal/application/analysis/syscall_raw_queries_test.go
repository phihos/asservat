package analysis

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

func rawSyscallAdmissionFixture(t *testing.T) (*projectionFixture, *packetQueryLedgerFixture, value.RawSyscallQueryRequest) {
	f := newProjectionFixture(t)
	f.ready = false
	s := &f.a.Scope
	selection, e := value.NormalizeSyscallSelection(s.CaseID, s.ArtifactID, value.SyscallQueryView, "", 10, []string{"read"}, false)
	if e != nil {
		t.Fatal(e)
	}
	source, ok := value.LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, value.SyscallQueryDisplayVersion)
	if !ok {
		t.Fatal("raw source unregistered")
	}
	s.NativeType, s.SourceFormat, s.SourceProjectionDigest, s.DisplayVersion = source.NativeType, source.Format, source.ProjectionDigest, source.DisplayVersion
	s.Selection, s.Syscalls = value.LineSelection{}, selection.Window()
	s.RawGrantID = f.next()
	f.a.Grant = value.ContextQueryGrant{ParentID: s.RawGrantID, ChildID: f.next()}
	f.i.Scopes = append(f.i.Scopes, "evidence:raw")
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.SyscallQueryWorkerBytes, value.SyscallQueryWorkerBytes
	candidate := s.Candidate()
	candidate.Syscalls = value.SyscallWindow{}
	candidate.RawGrantID = ""
	f.s.SyscallRoutes = syscallRouteFixture{candidate}
	ledger := &packetQueryLedgerFixture{projectionFixture: f}
	f.s.Results.Ledger = ledger
	r := value.RawSyscallQueryRequest{CaseID: s.CaseID, ArtifactID: s.ArtifactID, GrantID: s.RawGrantID, IdempotencyKey: "raw-syscall-original", Selection: s.Syscalls}
	return f, ledger, r
}
func TestRawSyscallBeginPinsInvocationBeforeAdmissionAndReplay(t *testing.T) {
	f, ledger, r := rawSyscallAdmissionFixture(t)
	service, ok := f.s.RawSyscallQueries()
	if !ok {
		t.Fatal("not composed")
	}
	invoke := f.invocation("syscall_query")
	invoke.input = ContextQueryInput{RawSyscalls: r}
	d, e := service.Begin(t.Context(), f, invoke, r)
	if e != nil {
		t.Fatalf("raw query admission: %v", e)
	}
	if !d.Pending() || f.q.Scope.QueryUnits() != 4 || f.q.Scope.ReadBatches() != 2 || !f.q.InvocationKey.Valid() || f.q.Grant != f.a.Grant {
		t.Fatal("query funding or immutable grant/key missing")
	}
	id, deadline := d.Association().QueryID, d.QueryDeadline()
	invoke.outcome = d
	if e = d.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	replay := f.invocation("syscall_query")
	replay.input = ContextQueryInput{RawSyscalls: r}
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
	bad := f.invocation("syscall_query")
	bad.input = ContextQueryInput{RawSyscalls: changed}
	if d, e = service.Begin(t.Context(), f, bad, changed); e == nil || d != nil || f.starts != 1 || f.admissions != 1 {
		t.Fatal("changed key accepted", e)
	}
	if RawSyscallQueryRequestDigest(r) == PacketQueryRequestDigest(value.PacketQueryRequest{IdempotencyKey: r.IdempotencyKey}) {
		t.Fatal("request digest not domain separated")
	}
}

type rawSyscallReader struct {
	*projectionFixture
	wrong bool
}

func (f rawSyscallReader) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	r, e := f.projectionFixture.ReadProjection(ctx, start, owner)
	return rawSyscallRead{ContextProjectionRead: r, scope: f.a.Scope, wrong: f.wrong}, e
}

type rawSyscallRead struct {
	ContextProjectionRead
	scope value.ContextProjectionScope
	wrong bool
}

func (r rawSyscallRead) Projection(context.Context) (value.ProjectionResult, error) {
	s := r.scope
	n := uint64(1)
	page := value.SyscallArgumentPage{Version: s.Version, TotalMatching: 1, SyscallRecordCounts: value.SyscallRecordCounts{RecordCount: 1}, Events: []artifact.RawArgumentEvent{{Identity: artifact.ArgumentIdentity{PodUID: s.PodUID, ProcessRef: "p", ThreadRef: "t"}, Syscall: "read", ABI: "x86_64", Timestamp: "2026-11-05T10:00:00Z", Outcome: "success", DurationNS: &n, Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}}}}}
	if r.wrong {
		page.Events[0].Arguments[0].Value = "hex:0000"
	}
	return value.ProjectionResult{SyscallQuery: &page}, nil
}
func TestRawSyscallDeliveryOwnsValuesAndRefusesUnvalidatedOutput(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		t.Run(map[bool]string{false: "ready", true: "malformed"}[wrong], func(t *testing.T) {
			f, _, r := rawSyscallAdmissionFixture(t)
			f.ready = true
			f.s.Results.Reader = rawSyscallReader{f, wrong}
			s, _ := f.s.RawSyscallQueries()
			inv := f.invocation("syscall_query")
			inv.input = ContextQueryInput{RawSyscalls: r}
			d, e := s.Begin(t.Context(), f, inv, r)
			if wrong {
				if e == nil || d != nil || f.reads != 1 || f.lastRead == nil || !f.lastRead.closed {
					t.Fatal("malformed raw result delivered/unjoined", e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			p, ok := d.SyscallQuery()
			if !ok || p.Events[0].Arguments[0].Value != "decimal:0" {
				t.Fatal("raw page absent")
			}
			p.Events[0].Arguments[0].Value = "changed"
			*p.Events[0].DurationNS = 100
			again, _ := d.SyscallQuery()
			if again.Events[0].Arguments[0].Value != "decimal:0" || *again.Events[0].DurationNS != 1 {
				t.Fatal("borrowed raw page")
			}
			inv.outcome = d
			if e = d.Close(context.Background()); e != nil {
				t.Fatal(e)
			}
			if _, ok = d.SyscallQuery(); ok {
				t.Fatal("retained raw page after close")
			}
		})
	}
}

type rawApprovalProofFailure struct{}

func (rawApprovalProofFailure) Error() string                         { return "current source eligible; approval missing" }
func (rawApprovalProofFailure) RawSyscallQueryApprovalRequired() bool { return true }
func TestRawSyscallMissingApprovalIsOnlyBeforeAdmission(t *testing.T) {
	f, _, r := rawSyscallAdmissionFixture(t)
	r.GrantID = ""
	f.a.Scope.RawGrantID = ""
	f.a.Grant = value.ContextQueryGrant{}
	f.authorityErr = rawApprovalProofFailure{}
	s, _ := f.s.RawSyscallQueries()
	inv := f.invocation("syscall_query")
	inv.input = ContextQueryInput{RawSyscalls: r}
	d, e := s.Begin(t.Context(), f, inv, r)
	if d != nil || !RawSyscallQueryApprovalRequiredBeforeAdmission(e) || f.starts != 0 || f.admissions != 0 || f.reads != 0 {
		t.Fatal("missing approval became effect or opaque failure", e)
	}
}

func TestRawSyscallKeyCannotBecomePacketQuery(t *testing.T) {
	f, _, r := rawSyscallAdmissionFixture(t)
	s, _ := f.s.RawSyscallQueries()
	inv := f.invocation("syscall_query")
	inv.input = ContextQueryInput{RawSyscalls: r}
	d, e := s.Begin(t.Context(), f, inv, r)
	if e != nil {
		t.Fatal(e)
	}
	inv.outcome = d
	if e = d.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	compiler := &packetQueryCompilerFixture{}
	f.s.PacketCompiler = compiler
	f.s.PacketRoutes = packetQueryRoute{candidate: f.a.Scope.Candidate()}
	other := value.PacketQueryRequest{CaseID: r.CaseID, ArtifactID: r.ArtifactID, GrantID: r.GrantID, IdempotencyKey: r.IdempotencyKey, Fields: []value.PacketQueryField{value.PacketIndex}, MaxPackets: 1, MaxScanBytes: 1}
	pcq, _ := f.s.PacketQueries()
	call := f.invocation("pcap_query")
	call.input = ContextQueryInput{PacketQuery: other}
	if d, e = pcq.Begin(t.Context(), f, call, other); e == nil || d != nil || compiler.calls != 0 || f.admissions != 1 || f.starts != 1 || f.reads != 0 {
		t.Fatal("cross-tool key caused compile/admission/read", e)
	}
}

func TestRawSyscallReplayRegistrationKeepsOriginalGrantAndControl(t *testing.T) {
	for _, mode := range []string{"registered", "missing-facet", "registration-failed", "changed-mac", "changed-grant", "cancelled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f, ledger, r := rawSyscallAdmissionFixture(t)
			service, _ := f.s.RawSyscallQueries()
			first := f.invocation("syscall_query")
			first.input = ContextQueryInput{RawSyscalls: r}
			d, e := service.Begin(t.Context(), f, first, r)
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
				service, _ = f.s.RawSyscallQueries()
			}
			if mode == "registration-failed" {
				ledger.registerErr = value.ErrUnavailable
			}
			if mode == "changed-grant" {
				f.a.Grant.ChildID = f.next()
			}
			if mode == "expired" {
				f.refresh(original.Deadline.Add(time.Millisecond))
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				ledger.registerHook = cancel
			}
			replay := f.invocation("syscall_query")
			replay.input = ContextQueryInput{RawSyscalls: r}
			if mode == "changed-mac" {
				replay.call.InputDigest[0] ^= 1
			}
			d, e = service.Begin(ctx, f, replay, r)
			if mode == "registered" {
				if e != nil || d == nil || !d.Pending() || d.Effect() != ContextQueryReplayed || d.Association().QueryID != original.ID || !d.QueryDeadline().Equal(original.Deadline) || ledger.registrations != 1 {
					t.Fatal("raw registered replay", e)
				}
				replay.outcome = d
				if e = d.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
			} else if e == nil || d != nil {
				t.Fatal("raw replay bypassed registration/current authority", mode)
			}
			if !f.q.Equal(original) || f.polls != 0 || f.reads != 0 || f.batches != 0 || f.admissions != 1 || f.starts != 1 || f.observations != 1 {
				t.Fatal("raw replay changed original query or caused work", mode)
			}
		})
	}
}
