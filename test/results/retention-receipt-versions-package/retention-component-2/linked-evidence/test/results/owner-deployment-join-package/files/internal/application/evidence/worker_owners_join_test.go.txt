package evidence

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

func TestWorkerOwnerWrappersJoinOriginalSQLBeforeDependencyClose(t *testing.T) {
	for _, mode := range []string{"claim", "lookup", "release"} {
		t.Run(mode, func(t *testing.T) {
			router, ops := routeTestSetup(t, 1, 1)
			entered, release := make(chan context.Context, 1), make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			var resourceClosed atomic.Bool
			var claims, reads, releases atomic.Int32
			block := func(ctx context.Context) {
				entered <- ctx
				<-release
				if resourceClosed.Load() {
					t.Error("dependency closed before original wrapper SQL call returned")
				}
			}
			var lease value.WorkerOwnerLease
			store := testWorkerOwnerStore{
				claim: func(ctx context.Context, request value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
					claims.Add(1)
					lease = value.WorkerOwnerLease{Request: request, Fence: 3, Started: time.Now().UTC()}
					if mode == "claim" {
						block(ctx)
					}
					return lease, nil
				},
				read: func(ctx context.Context, session, worker string) (value.WorkerOwnerLease, error) {
					reads.Add(1)
					if session != lease.Request.SessionID || worker != lease.Request.WorkerID {
						t.Error("wrapper changed exact original locator")
					}
					if mode == "lookup" {
						block(ctx)
					}
					return lease, nil
				},
				release: func(ctx context.Context, original value.WorkerOwnerLease) error {
					releases.Add(1)
					if !original.Equal(lease) {
						t.Error("cleanup changed original SQL fence")
					}
					if mode == "release" {
						block(ctx)
					}
					return nil
				},
			}
			const id = "10000000-0000-4000-8000-000000000888"
			owners := &WorkerRequestOwners{Router: router, Store: store, PodUID: id, ProcessEpoch: id, NewID: func() string { return id }}
			var handle *WorkerOwnerRegistration
			if mode != "claim" {
				var err error
				handle, err = owners.Register(context.Background(), ops[0])
				if err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			var result error
			go func() {
				switch mode {
				case "claim":
					handle, result = owners.Register(context.Background(), ops[0])
				case "lookup":
					delivery, err := handle.BeginWorkerEnrollment(context.Background(), handle.Lease(), []byte("token"), []byte("csr"))
					result = err
					if delivery != nil {
						delivery.Close()
					}
				case "release":
					result = handle.Close(context.Background())
				}
				close(done)
			}()
			defer func() { finish(); <-done; router.CloseAndJoin() }()
			var original context.Context
			select {
			case original = <-entered:
			case <-time.After(time.Second):
				t.Fatal("wrapper did not enter original SQL boundary")
			}
			until, bounded := original.Deadline()
			if !bounded || until.After(ops[0].bound()) || mode == "release" && time.Until(until) > 5*time.Second {
				t.Fatal("wrapper SQL did not retain its original bound")
			}
			closed := make(chan struct{})
			go func() { router.CloseAndJoin(); resourceClosed.Store(true); close(closed) }()
			defer func() { finish(); <-closed }()
			select {
			case <-router.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("router shutdown did not cancel admission")
			}
			if mode != "release" {
				select {
				case <-original.Done():
				case <-time.After(time.Second):
					t.Fatal("shutdown did not reach original wrapper read/claim")
				}
			}
			select {
			case <-closed:
				t.Error("router closed dependencies before admitted wrapper SQL joined")
			case <-time.After(50 * time.Millisecond):
			}
			if end, _ := original.Deadline(); !end.Equal(until) {
				t.Error("shutdown replaced the wrapper's original deadline")
			}
			finish()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("released nested wrapper did not join")
			}
			<-done
			if mode == "release" && result != nil || mode != "release" && result == nil {
				t.Error("wrapper changed its original completion semantics", result)
			}
			if _, err := owners.Register(context.Background(), ops[0]); err == nil {
				t.Error("closed router accepted new wrapper SQL")
			}
			if handle != nil {
				_ = handle.Close(context.Background())
			}
			wantRead, wantRelease := int32(0), int32(0)
			if mode == "lookup" {
				wantRead = 1
			}
			if mode == "release" {
				wantRelease = 1
			}
			if claims.Load() != 1 || reads.Load() != wantRead || releases.Load() != wantRelease {
				t.Fatal("shutdown initiated SQL after closing dependency admission", claims.Load(), reads.Load(), releases.Load())
			}
		})
	}
}
