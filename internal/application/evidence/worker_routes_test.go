package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type routeBindingsFunc func(context.Context, string, string) (value.DownloadWorkerIdentity, error)

func (f routeBindingsFunc) ReadDownloadWorkerEnrollment(ctx context.Context, s, w string) (value.DownloadWorkerIdentity, error) {
	return f(ctx, s, w)
}

type routeAuthorityFunc func(context.Context, string, artifact.DownloadScope) (artifact.DownloadAuthority, error)

func (f routeAuthorityFunc) CheckDownload(ctx context.Context, c string, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	return f(ctx, c, s)
}

// Synthetic current rights/registry for routing bounds only. Issuance itself is
// separately tested with the actual authority, SQL and audit implementations.
func routeTestWorker(t *testing.T, n int) value.DownloadWorker {
	t.Helper()
	id := fmt.Sprintf("10000000-0000-4000-8000-%012d", n)
	installation := "10000000-0000-4000-8000-000000000999"
	now := time.Now().UTC()
	rev := identity.Revision{UID: id, Generation: 1, Digest: [32]byte{1}}
	p := value.DownloadWorkerProfile{Configuration: rev, InstallationID: installation, ClusterID: id, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "acquire", ServiceAccountUID: "account", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "target-namespace", WorkloadUID: "workload", PodUID: "target-pod", Version: artifact.Digest{2}, Principal: identity.Principal{Issuer: "https://synthetic.invalid", Subject: fmt.Sprint(n), ClientID: "console", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{3}, DecisionDigest: artifact.Digest{4}, IdentityRevision: rev, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}
	a.Environment = artifact.DownloadEnvironment{RootID: id, InstallationID: installation, Region: "test", StoreID: id, RecoveryEpoch: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Principal: scope.Principal, Revision: rev, RecoveryRevision: rev, ObservedAt: now, ValidUntil: a.ValidUntil}
	i := value.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: p, Authority: a, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	j := value.DownloadWorkerJob{IntentID: id, UID: "job", Spec: artifact.Digest{5}}
	w := value.DownloadWorker{Intent: i, Job: j, Binding: value.KeyWorkerBinding{InstallationID: installation, DownloadID: id, ClusterID: id, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: i.JobName(), JobUID: j.UID, JobSpec: j.Spec, Pod: "worker", PodUID: id, PodSpec: artifact.Digest{6}}}
	if !w.Valid() {
		t.Fatal("invalid synthetic worker")
	}
	return w
}
func routeTestSetup(t *testing.T, count, limit int) (*WorkerEnrollmentRouter, []*WorkerEnrollmentOperation) {
	t.Helper()
	workers := make(map[string]value.DownloadWorker)
	ops := make([]*WorkerEnrollmentOperation, count)
	for i := range ops {
		w := routeTestWorker(t, i+1)
		workers[w.Intent.ID] = w
		authority := routeAuthorityFunc(func(ctx context.Context, credential string, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
			a := w.Intent.Authority
			if credential != w.Intent.ID || scope != a.Scope || ctx.Err() != nil {
				return a, artifact.ErrDownloadExpired
			}
			n := time.Now()
			a.CheckedAt = n
			a.ValidUntil = n.Add(5 * time.Second)
			a.Environment.ObservedAt = n
			a.Environment.ValidUntil = a.ValidUntil
			return a, nil
		})
		ops[i] = &WorkerEnrollmentOperation{parent: context.Background(), until: time.Now().Add(30 * time.Second), credential: w.Intent.ID, target: workerTarget(w), scope: w.Intent.Authority.Scope, service: WorkerEnrollmentCoordinator{Authority: authority, Now: time.Now}, proofs: func(DownloadPeerToken) (WorkerEnrollmentProofReader, error) { return nil, artifact.ErrInvalid }}
	}
	bindings := routeBindingsFunc(func(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
		w, ok := workers[worker]
		if !ok || w.Intent.SessionID != session || ctx.Err() != nil {
			return value.DownloadWorkerIdentity{}, artifact.ErrInvalid
		}
		n := time.Now()
		return value.DownloadWorkerIdentity{Worker: w, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
	})
	r, err := NewWorkerEnrollmentRouter(context.Background(), ops[0].target.InstallationID, bindings, time.Now, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r, ops
}

func TestWorkerRoutesRequireCurrentOwnerAndExactWorker(t *testing.T) {
	for _, mode := range []string{"valid", "credential", "actor", "worker", "pod", "start", "end", "installation", "authority-installation", "expired", "cancelled", "binding-expired"} {
		t.Run(mode, func(t *testing.T) {
			r, ops := routeTestSetup(t, 1, 1)
			op := ops[0]
			switch mode {
			case "credential":
				op.credential = "another-user"
			case "actor":
				op.scope.Principal.Subject = "another-user"
			case "worker":
				op.target.WorkerID = "10000000-0000-4000-8000-000000000123"
			case "pod":
				op.target.PodUID = "10000000-0000-4000-8000-000000000123"
			case "start":
				op.target.CreatedAt = op.target.CreatedAt.Add(time.Second)
			case "end":
				op.target.RunUntil = op.target.RunUntil.Add(-time.Second)
			case "installation":
				op.target.InstallationID = op.target.PodUID
			case "authority-installation":
				previous := op.service.Authority
				op.service.Authority = routeAuthorityFunc(func(ctx context.Context, credential string, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
					a, err := previous.CheckDownload(ctx, credential, scope)
					a.Environment.InstallationID = op.target.PodUID
					return a, err
				})
			case "expired":
				op.until = time.Now().Add(-time.Second)
			case "cancelled":
				ctx, cancel := context.WithCancel(op.parent)
				cancel()
				op.parent = ctx
			case "binding-expired":
				previous := r.bindings
				r.bindings = routeBindingsFunc(func(ctx context.Context, s, w string) (value.DownloadWorkerIdentity, error) {
					o, e := previous.ReadDownloadWorkerEnrollment(ctx, s, w)
					o.FreshUntil = time.Now().Add(-time.Second)
					return o, e
				})
			}
			h, err := r.Register(context.Background(), op)
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				h.Close()
			} else if err == nil {
				t.Fatal("invalid route accepted")
			}
			r.mu.Lock()
			used := r.used
			r.mu.Unlock()
			if used != 0 {
				t.Fatal("failed/closed registration leaked slot", used)
			}
		})
	}
}

func TestWorkerRoutesRejectStaleRegistrationAfterIO(t *testing.T) {
	for _, mode := range []string{"authority-expired", "owner-expired", "caller-cancelled", "parent-cancelled", "router-closed"} {
		t.Run(mode, func(t *testing.T) {
			r, ops := routeTestSetup(t, 1, 1)
			op := ops[0]
			caller, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			op.parent = parent
			previous := r.bindings
			r.bindings = routeBindingsFunc(func(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
				o, err := previous.ReadDownloadWorkerEnrollment(ctx, session, worker)
				// Simulate a provider completing with an apparently valid result
				// after another bound expires. Registration must recheck it.
				switch mode {
				case "authority-expired":
					n := time.Now().Add(6 * time.Second)
					r.now = func() time.Time { return n }
					o.ObservedAt, o.FreshUntil = n, n.Add(time.Second)
				case "owner-expired":
					n := op.until.Add(time.Second)
					r.now = func() time.Time { return n }
				case "caller-cancelled":
					cancelCaller()
				case "parent-cancelled":
					cancelParent()
					<-ctx.Done()
				case "router-closed":
					r.Close()
				}
				return o, err
			})
			if _, err := r.Register(caller, op); err == nil {
				t.Fatal("stale registration accepted")
			}
			r.mu.Lock()
			used, entries := r.used, len(r.entries)
			r.mu.Unlock()
			if used != 0 || entries != 0 {
				t.Fatal("failed registration retained owner/capacity", used, entries)
			}
		})
	}
}

func TestWorkerRoutesKeepConcurrentWorkerTokensSeparate(t *testing.T) {
	r, ops := routeTestSetup(t, 2, 2)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	results := make(chan error, 2)
	for _, op := range ops {
		op.proofs = func(token DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
			entered <- struct{}{}
			<-release
			b, err := token.ReadDownloadPeerToken(context.Background())
			defer clear(b)
			if err != nil || string(b) != op.credential {
				t.Error("another active worker replaced the token")
			}
			return nil, artifact.ErrDownloadUnavailable
		}
		route, err := r.Register(context.Background(), op)
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		go func() {
			v := op.target
			d, err := r.BeginWorkerEnrollment(context.Background(), v.InstallationID, v.SessionID, v.WorkerID, []byte(op.credential), []byte("csr"))
			if d != nil {
				d.Close()
			}
			results <- err
		}()
	}
	for range ops {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("distinct active owners could not enter concurrently")
		}
	}
	once.Do(func() { close(release) })
	for range ops {
		select {
		case err := <-results:
			if !errors.Is(err, artifact.ErrDownloadUnavailable) {
				t.Fatal("unexpected routed proof result", err)
			}
		case <-time.After(time.Second):
			t.Fatal("routed call did not finish")
		}
	}
}

func TestWorkerRoutesBoundConcurrentRegistrationAndPreserveReplacement(t *testing.T) {
	r, ops := routeTestSetup(t, 8, 2)
	var wg sync.WaitGroup
	results := make(chan *WorkerEnrollmentRoute, 8)
	for _, op := range ops {
		wg.Go(func() {
			h, e := r.Register(context.Background(), op)
			if e == nil {
				results <- h
			}
		})
	}
	wg.Wait()
	close(results)
	var accepted []*WorkerEnrollmentRoute
	for h := range results {
		accepted = append(accepted, h)
	}
	if len(accepted) != 2 {
		t.Fatal("capacity mismatch", len(accepted))
	}
	for _, h := range accepted {
		h.Close()
	}
	one, err := r.Register(context.Background(), ops[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Register(context.Background(), ops[0]); !errors.Is(err, artifact.ErrDownloadConflict) {
		t.Fatal("duplicate owner", err)
	}
	one.Close()
	two, err := r.Register(context.Background(), ops[0])
	if err != nil {
		t.Fatal(err)
	}
	one.Close() // A delayed old close must never remove the newer owner.
	r.mu.Lock()
	got := r.entries[two.key]
	r.mu.Unlock()
	if got != two {
		t.Fatal("old owner erased replacement")
	}
	two.Close()
}

func TestWorkerRoutesKeepClosingWorkChargedUntilItReturns(t *testing.T) {
	r, ops := routeTestSetup(t, 2, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	ops[0].proofs = func(DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
		close(entered)
		<-release
		return nil, artifact.ErrDownloadUnavailable
	}
	h, err := r.Register(context.Background(), ops[0])
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	target := ops[0].target
	go func() {
		d, e := r.BeginWorkerEnrollment(context.Background(), target.InstallationID, target.SessionID, target.WorkerID, []byte("token"), []byte("csr"))
		if d != nil {
			d.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request not routed")
	}
	if _, e := r.BeginWorkerEnrollment(context.Background(), target.InstallationID, target.SessionID, target.WorkerID, []byte("token"), []byte("csr")); !errors.Is(e, artifact.ErrDownloadConflict) {
		t.Fatal("parallel request admitted", e)
	}
	h.Close()
	if _, e := r.Register(context.Background(), ops[1]); !errors.Is(e, artifact.ErrDownloadCapacity) {
		t.Fatal("closing work refunded early", e)
	}
	once.Do(func() { close(release) })
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed work succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("call did not exit")
	}
	next, e := r.Register(context.Background(), ops[1])
	if e != nil {
		t.Fatal("finished slot not released", e)
	}
	next.Close()
}

func TestWorkerRoutesCancelIdleOwnersAndCloseRouter(t *testing.T) {
	r, ops := routeTestSetup(t, 2, 1)
	ctx, cancel := context.WithCancel(context.Background())
	h, err := r.Register(ctx, ops[0])
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-h.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("owner cancellation lost")
	}
	next, err := r.Register(context.Background(), ops[1])
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	select {
	case <-next.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("router shutdown lost")
	}
	if _, err = r.Register(context.Background(), ops[0]); err == nil {
		t.Fatal("closed router revived")
	}
}
