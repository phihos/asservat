package integration

import (
	"context"
	"reflect"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// This derives bounded authored control for the fixture's initial key digest.
// Its admitted program is a controlled typed value, not a libpcap compilation
// claim. Replay must find that exact accepted program without compiling again.
func packetQueryReplayRequest(scope query.ContextProjectionScope, key string) query.PacketQueryRequest {
	s := scope.PacketQuery.Selection()
	return query.PacketQueryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, GrantID: scope.RawGrantID, IdempotencyKey: key, Fields: s.Fields, StartTime: s.StartTime, EndTime: s.EndTime, TCPFlags: s.TCPFlags, FramePrefix: s.FramePrefix, MaxPackets: s.MaxPackets, MaxScanBytes: s.MaxScanBytes}
}

type replayCompositionInvocation struct {
	request query.ContextQueryRequest
	input   query.PacketQueryRequest
}

func (i replayCompositionInvocation) Invocation(ctx context.Context) (query.ContextQueryCall, error) {
	if ctx.Err() != nil || !i.request.Valid(time.Now()) {
		return query.ContextQueryCall{}, query.ErrUnavailable
	}
	return i.request.Call, nil
}
func (i replayCompositionInvocation) CheckInput(ctx context.Context, input app.ContextQueryInput) error {
	if ctx.Err() != nil || !reflect.DeepEqual(input, app.ContextQueryInput{PacketQuery: app.NormalizePacketQueryRequest(i.input)}) {
		return query.ErrUnavailable
	}
	return nil
}
func (i replayCompositionInvocation) CheckIntent(ctx context.Context, call query.ContextQueryCall) error {
	if ctx.Err() != nil || call != i.request.Call {
		return query.ErrUnavailable
	}
	return nil
}

// This helper never fabricates an acknowledged public outcome or discloses a
// page. The enclosing fixture owns the real C8 Finish after this pending replay.
func (replayCompositionInvocation) CheckOutcome(context.Context, *app.ContextProjectionDelivery) error {
	return query.ErrUnavailable
}

type replayCompositionNoEffects struct{ calls []string }

func (p *replayCompositionNoEffects) fail(name string) error {
	p.calls = append(p.calls, name)
	return query.ErrUnavailable
}
func (p *replayCompositionNoEffects) ResolveProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (query.ContextProjectionCandidate, error) {
	return query.ContextProjectionCandidate{}, p.fail("route")
}
func (p *replayCompositionNoEffects) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (query.ContextProjectionCandidate, error) {
	return query.ContextProjectionCandidate{}, p.fail("packet-route")
}
func (p *replayCompositionNoEffects) CompilePacketQueryFilter(context.Context, string) (query.PacketQueryProgram, error) {
	return query.PacketQueryProgram{}, p.fail("compile")
}
func (p *replayCompositionNoEffects) ContextQueryPlan(context.Context, query.ContextProjectionAuthority) (query.ContextQueryPlan, error) {
	return query.ContextQueryPlan{}, p.fail("plan")
}
func (p *replayCompositionNoEffects) ProjectionWorkerRoom(context.Context, query.ContextQuery) error {
	return p.fail("worker-room")
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

// The ledger, current C3 and recovery below are the fixture's actual compiled-
// role adapters and C8 has already acknowledged the passed call. Human/bootstrap
// facts remain synthetic. This is C18+SQL composition, not browser/installed proof.
func qualifyPacketQueryReplayApplication(t *testing.T, ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, input query.PacketQueryRequest, caller identities.CurrentIdentity, ledger app.ContextQueryLedger, authority app.CurrentContextProjectionAuthority, recovery app.ContextProjectionRecovery) {
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
	}}, Recovery: recovery, PacketRoutes: unused, PacketCompiler: unused, Plans: unused, Workers: unused}
	reads, ok := service.PacketQueries()
	if !ok {
		t.Fatal("replay service unavailable")
	}
	delivery, err := reads.Begin(ctx, caller, replayCompositionInvocation{r, input}, input)
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
		t.Fatal("initial replay exposed a page")
	}
	if len(unused.calls) != 0 {
		t.Fatal("replay called new-work ports", unused.calls)
	}
}
