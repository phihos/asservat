package integration

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// This derives bounded authored control for the fixture's initial key digest.
// Its admitted program is a controlled typed value, not a libpcap compilation
// claim. Replay must find that exact accepted program without compiling again.
func packetQueryReplayRequest(scope query.ContextProjectionScope, key string) query.PacketQueryRequest {
	s := scope.PacketQuery.Selection()
	return query.PacketQueryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, GrantID: scope.RawGrantID, IdempotencyKey: key, Fields: s.Fields, StartTime: s.StartTime, EndTime: s.EndTime, TCPFlags: s.TCPFlags, FramePrefix: s.FramePrefix, MaxPackets: s.MaxPackets, MaxScanBytes: s.MaxScanBytes}
}

type replayCompositionNoEffects struct{ calls []string }

func (p *replayCompositionNoEffects) fail(name string) error {
	p.calls = append(p.calls, name)
	return query.ErrUnavailable
}
func (p *replayCompositionNoEffects) ResolveProjectionRoute(context.Context, string, string, identity.Identity) (query.ContextProjectionCandidate, error) {
	return query.ContextProjectionCandidate{}, p.fail("route")
}
func (p *replayCompositionNoEffects) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity) (query.ContextProjectionCandidate, error) {
	return query.ContextProjectionCandidate{}, p.fail("packet-route")
}
func (p *replayCompositionNoEffects) ResolveSyscallProjectionRoute(context.Context, string, string, identity.Identity) (query.ContextProjectionCandidate, error) {
	return query.ContextProjectionCandidate{}, p.fail("syscall-route")
}
func (p *replayCompositionNoEffects) CompilePacketQueryFilter(context.Context, string) (query.PacketQueryProgram, error) {
	return query.PacketQueryProgram{}, p.fail("compile")
}
func (p *replayCompositionNoEffects) ContextQueryPlan(context.Context, query.ContextProjectionAuthority) (query.ContextQueryPlan, error) {
	return query.ContextQueryPlan{}, p.fail("plan")
}
func (p *replayCompositionNoEffects) AdmitProjectionWorker(context.Context, query.ContextQuery, app.ContextProjectionRequestOwner) error {
	return p.fail("worker-admission")
}
func (p *replayCompositionNoEffects) ObserveProjectionWorker(context.Context, query.ContextQuery, app.ContextProjectionRequestOwner) (app.ContextProjectionWorkerObservation, error) {
	return app.ContextProjectionWorkerObservation{}, p.fail("worker-observe")
}
func (p *replayCompositionNoEffects) ReadProjection(context.Context, query.ContextReadStart, app.ContextProjectionRequestOwner) (app.ContextProjectionRead, error) {
	return nil, p.fail("read")
}

// The ledger and current C3 below are the fixture's actual compiled-
// role adapters for the passed call. Human/bootstrap
// facts remain synthetic. This is C18+SQL composition, not browser/installed proof.
func qualifyPacketQueryReplayApplication(t *testing.T, ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, input query.PacketQueryRequest, caller identities.CurrentIdentity, ledger app.ContextQueryLedger, authority app.CurrentContextProjectionAuthority) {
	t.Helper()
	if input.IdempotencyKey != q.InvocationKey.Key || app.PacketQueryRequestDigest(input) != q.InvocationKey.RequestDigest {
		t.Fatal("replay fixture does not bind original normalized request")
	}
	unused := &replayCompositionNoEffects{}
	allocated := 0
	service := app.ContextProjectionService{Results: app.ContextProjectionResults{RootID: q.Scope.RootID, InstallationID: q.Plan.InstallationID, HubProcessEpoch: r.HubProcessEpoch, Authority: authority, Ledger: ledger, Reader: unused, Now: time.Now, NewID: func() string {
		allocated++
		if allocated == 1 {
			return r.OwnerID
		}
		return custodyID()
	}}, PacketRoutes: unused, PacketCompiler: unused, Plans: unused, Workers: unused}
	reads, ok := service.PacketQueries()
	if !ok {
		t.Fatal("replay service unavailable")
	}
	delivery, err := reads.Begin(ctx, caller, r.Call.ID, input)
	if delivery != nil {
		defer func() {
			if err := delivery.Close(context.WithoutCancel(ctx)); err != nil {
				t.Error("pending replay close", err)
			}
		}()
	}
	if err != nil || delivery == nil {
		t.Fatal("actual C18 original-key Begin replay", err)
	}
	if !delivery.Pending() || delivery.Effect() != app.ContextQueryReplayed || delivery.Association().QueryID != q.ID || delivery.Association().OperationID != r.Call.ID || delivery.Association().BatchID != "" || !delivery.QueryDeadline().Equal(q.Deadline) {
		t.Fatal("replay changed original association/deadline or charged a read")
	}
	if _, ok = delivery.PacketQuery(); ok {
		t.Fatal("initial replay exposed a packet page")
	}
	if _, ok = delivery.SyscallQuery(); ok {
		t.Fatal("initial replay exposed a syscall page")
	}
	if len(unused.calls) != 0 {
		t.Fatal("replay called new-work ports", unused.calls)
	}
}

func rawSyscallQueryReplayRequest(scope query.ContextProjectionScope, key string) query.RawSyscallQueryRequest {
	return query.RawSyscallQueryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, GrantID: scope.RawGrantID, IdempotencyKey: key, Selection: scope.Syscalls}
}

func qualifyRawSyscallQueryReplayApplication(t *testing.T, ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, input query.RawSyscallQueryRequest, caller identities.CurrentIdentity, ledger app.ContextQueryLedger, authority app.CurrentContextProjectionAuthority) {
	t.Helper()
	if input.IdempotencyKey != q.InvocationKey.Key || app.RawSyscallQueryRequestDigest(input) != q.InvocationKey.RequestDigest {
		t.Fatal("replay fixture does not bind original normalized request")
	}
	unused := &replayCompositionNoEffects{}
	allocated := 0
	service := app.ContextProjectionService{Results: app.ContextProjectionResults{RootID: q.Scope.RootID, InstallationID: q.Plan.InstallationID, HubProcessEpoch: r.HubProcessEpoch, Authority: authority, Ledger: ledger, Reader: unused, Now: time.Now, NewID: func() string {
		allocated++
		if allocated == 1 {
			return r.OwnerID
		}
		return custodyID()
	}}, PacketRoutes: unused, PacketCompiler: unused, Plans: unused, Workers: unused}
	service.SyscallRoutes = unused
	reads, ok := service.RawSyscallQueries()
	if !ok {
		t.Fatal("replay service unavailable")
	}
	delivery, err := reads.Begin(ctx, caller, r.Call.ID, input)
	if delivery != nil {
		defer func() {
			if err := delivery.Close(context.WithoutCancel(ctx)); err != nil {
				t.Error("pending replay close", err)
			}
		}()
	}
	if err != nil || delivery == nil {
		t.Fatal("actual C18 original-key Begin replay", err)
	}
	if !delivery.Pending() || delivery.Effect() != app.ContextQueryReplayed || delivery.Association().QueryID != q.ID || delivery.Association().OperationID != r.Call.ID || delivery.Association().BatchID != "" || !delivery.QueryDeadline().Equal(q.Deadline) {
		t.Fatal("replay changed original association/deadline or charged a read")
	}
	if _, ok = delivery.PacketQuery(); ok {
		t.Fatal("initial replay exposed a packet page")
	}
	if _, ok = delivery.SyscallQuery(); ok {
		t.Fatal("initial replay exposed a syscall page")
	}
	if len(unused.calls) != 0 {
		t.Fatal("replay called new-work ports", unused.calls)
	}
}
