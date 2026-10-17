package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Separate owner pools/registries use real SQL fences; Pod/process identities
// and worker proofs are explicit synthetic inputs, not hub process attestation.
func qualifyWorkerOwners(t *testing.T, ctx context.Context, w value.DownloadWorker, f workerEnrollmentFixture, guards postgres.DownloadTransactionGuards, authority func() artifact.DownloadAuthority, refresh func() error, cancelSession func() error, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool) {
	t.Helper()
	poolA := poolFor("worker_owner_runtime", "synthetic-worker-owner")
	defer poolA.Close()
	poolB := poolFor("worker_owner_runtime", "synthetic-worker-owner")
	defer poolB.Close()
	readPool := poolFor("worker_owner_read_runtime", "synthetic-worker-owner-read")
	defer readPool.Close()
	newStore := func(pool *pgxpool.Pool) *postgres.WorkerOwners {
		s, err := postgres.NewWorkerOwners(ctx, pool, w.Intent.Authority.Scope.RootID, w.Intent.Profile, guards)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	stores := []*postgres.WorkerOwners{newStore(poolA), newStore(poolB)}
	reader, err := postgres.NewWorkerRouting(ctx, readPool, w.Intent.Authority.Scope.RootID, w.Intent.Profile.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	owners := make([]*evidence.WorkerRequestOwners, 2)
	for i := range owners {
		router, err := evidence.NewWorkerEnrollmentRouter(ctx, w.Binding.InstallationID, f.bindings, time.Now, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer router.Close()
		owners[i] = &evidence.WorkerRequestOwners{Router: router, Store: stores[i], PodUID: custodyID(), ProcessEpoch: custodyID(), NewID: custodyID}
	}
	newOperation := func(parent context.Context) *evidence.WorkerEnrollmentOperation {
		target := value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
		op, err := evidence.NewWorkerEnrollmentOperation(parent, *f.service, func(tokens evidence.DownloadPeerToken) (evidence.WorkerEnrollmentProofReader, error) {
			return channelSQLProof{tokens, w}, nil
		}, "synthetic-reference", target, w.Intent.Authority.Scope)
		if err != nil {
			t.Fatal(err)
		}
		return op
	}
	first, err := owners[0].Register(ctx, newOperation(ctx))
	if err != nil {
		t.Fatal("register first SQL owner", err)
	}
	defer first.Close(ctx)
	lease := first.Lease()
	receiver := &evidence.WorkerRequestOwners{Router: owners[0].Router, PodUID: owners[0].PodUID, ProcessEpoch: owners[0].ProcessEpoch}
	delivery, err := receiver.BeginOwnedWorkerEnrollment(ctx, lease, []byte("synthetic.first.token"), f.csr)
	if err != nil {
		t.Fatal("exact shared/local owner could not enroll", err)
	}
	certificate := delivery.Certificate()
	delivery.Close()
	if _, err = owners[1].Register(ctx, newOperation(ctx)); !errors.Is(err, artifact.ErrDownloadConflict) {
		t.Fatal("another hub took an active owner", err)
	}
	got, err := reader.ReadWorkerOwner(ctx, w.Intent.SessionID, w.Intent.ID)
	if err != nil || got != lease {
		t.Fatal("independent reader could not locate exact owner", err)
	}
	if _, err = reader.ReadWorkerOwner(ctx, custodyID(), w.Intent.ID); err == nil {
		t.Fatal("foreign session found owner")
	}
	again, err := stores[0].ClaimWorkerOwner(ctx, w, authority(), lease.Request)
	if err != nil || again != lease {
		t.Fatal("claim reconciliation changed fence/deadline", err)
	}
	renewed := lease.Request
	renewed.Until = renewed.Until.Add(-time.Second)
	if _, err = stores[0].ClaimWorkerOwner(ctx, w, authority(), renewed); err == nil {
		t.Fatal("same request changed original timing")
	}
	if err = first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := owners[1].Register(ctx, newOperation(ctx))
	if err != nil || second.Lease().Fence != lease.Fence+1 {
		t.Fatal("released owner could not be replaced", err)
	}
	defer second.Close(ctx)
	if _, err = owners[0].BeginOwnedWorkerEnrollment(ctx, lease, []byte("synthetic.first.token"), f.csr); err == nil {
		t.Fatal("stale owner rerouted to its replacement")
	}
	replay, err := owners[1].BeginOwnedWorkerEnrollment(ctx, second.Lease(), []byte("synthetic.first.token"), f.csr)
	if err != nil {
		t.Fatal("new current owner could not replay audited certificate", err)
	}
	if replay.Certificate().Peer != certificate.Peer || f.issuer.calls.Load() != 1 {
		t.Fatal("owner replacement changed key or repeated signing")
	}
	replay.Close()
	if err = stores[0].ReleaseWorkerOwner(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if got, err = reader.ReadWorkerOwner(ctx, w.Intent.SessionID, w.Intent.ID); err != nil || got != second.Lease() {
		t.Fatal("old release erased replacement", err)
	}
	for _, q := range []string{
		"UPDATE download_worker_owner SET expires_at=expires_at+interval '1 microsecond' WHERE worker_id=$1",
		"UPDATE download_worker_owner SET pod_uid='00000000-0000-4000-8000-000000000001' WHERE worker_id=$1",
		"UPDATE download_worker_owner SET fence=fence+1,request_id='00000000-0000-4000-8000-000000000001' WHERE worker_id=$1",
		"DELETE FROM download_worker_owner WHERE worker_id=$1",
		"UPDATE download_worker SET retired_proof_json=convert_to('{}','UTF8') WHERE id=$1",
	} {
		if _, err = poolA.Exec(ctx, q, w.Intent.ID); err == nil {
			t.Fatal("owner role rewrote immutable lease or worker", q)
		}
	}
	if _, err = readPool.Exec(ctx, "UPDATE download_worker_owner SET released_at=clock_timestamp() WHERE worker_id=$1", w.Intent.ID); err == nil {
		t.Fatal("lookup role released owner")
	}
	if err = second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = poolA.Exec(ctx, "UPDATE download_worker_owner SET released_at=NULL WHERE worker_id=$1", w.Intent.ID); err == nil {
		t.Fatal("released owner revived")
	}
	newRequest := func(lifetime time.Duration) value.WorkerOwnerRequest {
		return value.WorkerOwnerRequest{ID: custodyID(), InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: custodyID(), ProcessEpoch: custodyID(), Until: time.Now().UTC().Add(lifetime).Truncate(time.Microsecond)}
	}
	// Fixture-only read diagnostic before admitting the original timed authority
	// used by the unchanged negative check and eight-way race. Public role/state counts identify retained parent pools without
	// recording identities, queries, tokens, or changing a connection budget.
	{
		call, end := context.WithTimeout(ctx, time.Second)
		var occupancy string
		err := admin.QueryRow(call, `SELECT coalesce(jsonb_agg(jsonb_build_object('role',role,'state',state,'connections',connections) ORDER BY role,state),'[]'::jsonb)::text FROM (SELECT usename AS role,coalesce(state,'unknown') AS state,count(*) AS connections FROM pg_stat_activity WHERE backend_type='client backend' AND datname=current_database() GROUP BY usename,state) AS counts`).Scan(&occupancy)
		end()
		if err != nil {
			t.Fatal("fixture connection occupancy unavailable", err)
		}
		t.Log("request-owner pre-race connection occupancy", occupancy)
		for i, pool := range []*pgxpool.Pool{poolA, poolB, readPool} {
			stat := pool.Stat()
			t.Logf("request-owner pool=%d total=%d idle=%d acquired=%d", i, stat.TotalConns(), stat.IdleConns(), stat.AcquiredConns())
		}
	}
	a := authority()
	wrong := a
	wrong.Scope.Principal.Subject = "another-developer"
	if _, err = stores[0].ClaimWorkerOwner(ctx, w, wrong, newRequest(20*time.Second)); err == nil {
		t.Fatal("foreign actor claimed owner")
	}
	type outcome struct {
		lease value.WorkerOwnerLease
		err   error
	}
	results := make(chan outcome, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		request := newRequest(20 * time.Second)
		wg.Go(func() {
			l, e := stores[i%2].ClaimWorkerOwner(ctx, w, a, request)
			results <- outcome{l, e}
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	var winner value.WorkerOwnerLease
	for r := range results {
		if r.err == nil {
			winners++
			winner = r.lease
		} else if !errors.Is(r.err, artifact.ErrDownloadConflict) {
			t.Fatal("unexpected claim race error", r.err)
		}
	}
	if winners != 1 || winner.Fence != second.Lease().Fence+1 {
		t.Fatal("parallel owner claim did not select one fence", winners)
	}
	if err = stores[0].ReleaseWorkerOwner(ctx, winner); err != nil {
		t.Fatal(err)
	}
	// Observe a real lock wait, then release it after the request's deadline.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT worker_id FROM download_worker_owner WHERE worker_id=$1 FOR UPDATE", w.Intent.ID); err != nil {
		t.Fatal(err)
	}
	expiring := newRequest(400 * time.Millisecond)
	done := make(chan error, 1)
	a = authority()
	go func() { _, e := stores[0].ClaimWorkerOwner(ctx, w, a, expiring); done <- e }()
	blocked := false
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='worker_owner_runtime' AND wait_event_type='Lock')").Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("owner request never reached row lock")
	}
	time.Sleep(max(0, time.Until(expiring.Until)+10*time.Millisecond))
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, artifact.ErrDownloadExpired) {
		t.Fatal("owner request renewed after lock wait", err)
	}
	if _, err = reader.ReadWorkerOwner(ctx, w.Intent.SessionID, w.Intent.ID); err == nil {
		t.Fatal("expired failed claim published an owner")
	}
	if err = refresh(); err != nil {
		t.Fatal(err)
	}
	short, err := stores[0].ClaimWorkerOwner(ctx, w, authority(), newRequest(150*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(max(0, time.Until(short.Request.Until)+10*time.Millisecond))
	if _, err = reader.ReadWorkerOwner(ctx, w.Intent.SessionID, w.Intent.ID); err == nil {
		t.Fatal("expired owner remained discoverable")
	}
	replacement, err := stores[1].ClaimWorkerOwner(ctx, w, authority(), newRequest(20*time.Second))
	if err != nil || replacement.Fence != short.Fence+1 {
		t.Fatal("expired owner prevented fresh current request", err)
	}
	if err = cancelSession(); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ReadWorkerOwner(ctx, w.Intent.SessionID, w.Intent.ID); err == nil {
		t.Fatal("cancelled download remained routable")
	}
	if _, err = stores[0].ClaimWorkerOwner(ctx, w, authority(), newRequest(20*time.Second)); err == nil {
		t.Fatal("cancelled download obtained another owner")
	}
	if err = stores[1].ReleaseWorkerOwner(ctx, replacement); err != nil {
		t.Fatal("expired authority prevented exact locator cleanup", err)
	}
}
