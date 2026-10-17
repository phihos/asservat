package evidence

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type testWorkerOwnerStore struct {
	claim   func(context.Context, value.WorkerOwnerRequest) (value.WorkerOwnerLease, error)
	release func(context.Context, value.WorkerOwnerLease) error
	read    func(context.Context, string, string) (value.WorkerOwnerLease, error)
}

func (s testWorkerOwnerStore) ClaimWorkerOwner(ctx context.Context, _ value.DownloadWorker, _ artifact.DownloadAuthority, r value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
	return s.claim(ctx, r)
}
func (s testWorkerOwnerStore) ReadWorkerOwner(ctx context.Context, session, worker string) (value.WorkerOwnerLease, error) {
	if s.read != nil {
		return s.read(ctx, session, worker)
	}
	return value.WorkerOwnerLease{}, artifact.ErrDownloadUnavailable
}
func (s testWorkerOwnerStore) ReleaseWorkerOwner(ctx context.Context, l value.WorkerOwnerLease) error {
	return s.release(ctx, l)
}

func TestWorkerOwnerRegistrationPreservesLocalLifetimeOnSQLFailure(t *testing.T) {
	for _, mode := range []string{"current", "uncertain-claim", "cancelled-claim", "foreign-return"} {
		t.Run(mode, func(t *testing.T) {
			router, ops := routeTestSetup(t, 1, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			op := ops[0]
			op.parent = ctx
			released := 0
			requestID := "10000000-0000-4000-8000-000000000888"
			store := testWorkerOwnerStore{
				claim: func(ctx context.Context, r value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
					if r.Until.After(op.until) || r.ID != requestID {
						t.Fatal("registration changed original operation")
					}
					l := value.WorkerOwnerLease{Request: r, Fence: 3, Started: time.Now().UTC()}
					switch mode {
					case "uncertain-claim":
						return value.WorkerOwnerLease{}, artifact.ErrDownloadUnavailable
					case "cancelled-claim":
						cancel()
						<-ctx.Done()
					case "foreign-return":
						l.Request.ID = op.target.PodUID
					}
					return l, nil
				},
				release: func(ctx context.Context, l value.WorkerOwnerLease) error {
					d, ok := ctx.Deadline()
					if ctx.Err() != nil || !ok || d.After(time.Now().Add(5*time.Second)) || l.Request.ID != requestID || l.Fence != 3 {
						t.Fatal("release lost exact fence or bounded cleanup")
					}
					released++
					return nil
				},
			}
			owners := &WorkerRequestOwners{Router: router, Store: store, PodUID: requestID, ProcessEpoch: requestID, NewID: func() string { return requestID }}
			h, err := owners.Register(ctx, op)
			if mode == "current" {
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				if err = h.Close(ctx); err != nil {
					t.Fatal(err)
				}
				if err = h.Close(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || h != nil {
				t.Fatal("failed registration retained ownership")
			}
			expected := 0
			if mode == "current" || mode == "cancelled-claim" {
				expected = 1
			}
			if released != expected {
				t.Fatal("unknown/foreign fence released or exact cleanup missed", released)
			}
			router.mu.Lock()
			used, entries := router.used, len(router.entries)
			router.mu.Unlock()
			if used != 0 || entries != 0 {
				t.Fatal("registration leaked local owner", used, entries)
			}
		})
	}
}

func TestWorkerOwnerLookupKeepsExactRegistrationAcrossReplacement(t *testing.T) {
	router, ops := routeTestSetup(t, 1, 2)
	var current value.WorkerOwnerLease
	reads := 0
	var duringRead func()
	store := testWorkerOwnerStore{
		claim: func(_ context.Context, r value.WorkerOwnerRequest) (value.WorkerOwnerLease, error) {
			current = value.WorkerOwnerLease{Request: r, Fence: current.Fence + 1, Started: time.Now().UTC()}
			return current, nil
		},
		release: func(context.Context, value.WorkerOwnerLease) error { return nil },
		read: func(context.Context, string, string) (value.WorkerOwnerLease, error) {
			reads++
			old := current
			if duringRead != nil {
				f := duringRead
				duringRead = nil
				f()
			}
			return old, nil
		},
	}
	id := "10000000-0000-4000-8000-000000000888"
	owners := &WorkerRequestOwners{Router: router, Store: store, PodUID: id, ProcessEpoch: id, NewID: func() string { return id }}
	first, err := owners.Register(context.Background(), ops[0])
	if err != nil {
		t.Fatal(err)
	}
	expected := first.Lease()
	// Force replacement after wire lookup but before the shared-store read returns.
	var replacement *WorkerOwnerRegistration
	duringRead = func() {
		if e := first.Close(context.Background()); e != nil {
			t.Fatal(e)
		}
		replacement, err = owners.Register(context.Background(), ops[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = owners.BeginOwnedWorkerEnrollment(context.Background(), expected, []byte("token"), []byte("csr")); err == nil {
		t.Fatal("old operation adopted replacement")
	}
	if replacement == nil || reads != 1 {
		t.Fatal("replacement race not exercised", reads)
	}
	defer replacement.Close(context.Background())
	if _, err = owners.BeginOwnedWorkerEnrollment(context.Background(), expected, []byte("token"), []byte("csr")); err == nil || reads != 1 {
		t.Fatal("stale wire lease reached shared store")
	}
	foreign := replacement.Lease()
	foreign.Request.ProcessEpoch = ops[0].target.PodUID
	if _, err = owners.BeginOwnedWorkerEnrollment(context.Background(), foreign, []byte("token"), []byte("csr")); err == nil || reads != 1 {
		t.Fatal("foreign process reached shared store")
	}
}
