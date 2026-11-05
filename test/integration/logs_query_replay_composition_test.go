package integration

import (
	app "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"testing"
	"time"
)

type logsReplayNoEffects struct{ replayCompositionNoEffects }

func (p *logsReplayNoEffects) ResolveLogProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (query.ContextProjectionCandidate, error) {
	p.calls = append(p.calls, "logs-route")
	return query.ContextProjectionCandidate{}, query.ErrUnavailable
}
func logsQueryReplayRequest(scope query.ContextProjectionScope, key string) query.RawLogQueryRequest {
	return query.RawLogQueryRequest{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, GrantID: scope.RawGrantID, IdempotencyKey: key, Selection: scope.Logs}
}

func qualifyLogsQueryReplayApplication(t *testing.T, ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, input query.RawLogQueryRequest, caller identities.CurrentIdentity, ledger app.ContextQueryLedger, authority app.CurrentContextProjectionAuthority, recovery app.ContextProjectionRecovery) {
	t.Helper()
	if input.IdempotencyKey != q.InvocationKey.Key || app.RawLogQueryRequestDigest(input) != q.InvocationKey.RequestDigest {
		t.Fatal("replay fixture does not bind original normalized request")
	}
	unused := &logsReplayNoEffects{}
	allocated := 0
	service := app.ContextProjectionService{Results: app.ContextProjectionResults{RootID: q.Scope.RootID, InstallationID: q.Plan.InstallationID, HubProcessEpoch: r.HubProcessEpoch, Authority: authority, Ledger: ledger, Reader: unused, Now: time.Now, NewID: func() string {
		allocated++
		if allocated == 1 {
			return r.OwnerID
		}
		return custodyID()
	}}, Recovery: recovery, PacketRoutes: unused, PacketCompiler: unused, Plans: unused, Workers: unused}
	service.LogRoutes = unused
	reads, ok := service.RawLogQueries()
	if !ok {
		t.Fatal("replay service unavailable")
	}
	delivery, err := reads.Begin(ctx, caller, replayCompositionInvocation{r, app.ContextQueryInput{RawLogs: input}}, input)
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
	if _, ok = delivery.Logs(); ok {
		t.Fatal("initial replay exposed logs page")
	}
	if len(unused.calls) != 0 {
		t.Fatal("replay called new-work ports", unused.calls)
	}
}
