package integration

import (
	"context"
	"crypto/x509"
	"slices"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	identityapp "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	workertransport "asservat.local/asservat/internal/transport/worker"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Synthetic session storage only. NewBrowserRequest, the current authority gate,
// SQL roles/locks, encrypted S3 audit, TLS and process-owned worker key are real.
// This is neither a deployed worker nor a Keycloak/Pod-proof/provider fixture.
type workerBrowserSession struct {
	initial  identity.Identity
	expires  time.Time
	interval time.Duration
}

func (s workerBrowserSession) Resolve(ctx context.Context, cookie string, refresh bool) (identityapp.SessionView, error) {
	if ctx.Err() != nil || cookie != "synthetic-worker-session" || refresh {
		return identityapp.SessionView{}, identity.ErrDenied
	}
	i := s.initial
	i.Groups, i.Scopes = slices.Clone(i.Groups), slices.Clone(i.Scopes)
	i.VerifiedAt = time.Now().UTC()
	i.ValidUntil = identity.Earlier(i.VerifiedAt.Add(s.interval), s.expires)
	return identityapp.SessionView{Identity: i, ExpiresAt: s.expires}, nil
}
func browserCurrentForWorkerTest(t *testing.T, ctx context.Context, gate authorizationapp.ContextDownloadAuthority, interval time.Duration) (identityapp.CurrentIdentity, time.Time) {
	t.Helper()
	// This existing fixture reference only seeds its synthetic session store.
	// No product CurrentIdentity path serializes or fabricates a bearer token.
	i, err := gate.Identities.Resolve(ctx, "synthetic-reference")
	if err != nil {
		t.Fatal(err)
	}
	current, v, err := identityapp.NewBrowserRequest(ctx, workerBrowserSession{i, time.Now().UTC().Add(time.Minute), interval}, "synthetic-worker-session", false, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return current, v.Identity.ValidUntil
}

type notifyingWorkerRegistry struct {
	source  evidence.WorkerEnrollmentBindings
	entered chan struct{}
	once    sync.Once
}

func (r *notifyingWorkerRegistry) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (value.DownloadWorkerIdentity, error) {
	r.once.Do(func() { close(r.entered) })
	return r.source.ReadDownloadWorkerEnrollment(ctx, session, worker)
}

func qualifyCurrentWorkerEnrollment(t *testing.T, ctx context.Context, w value.DownloadWorker, f workerEnrollmentFixture, admin *pgxpool.Pool) {
	t.Helper()
	gate, ok := f.service.Authority.(authorizationapp.ContextDownloadAuthority)
	if !ok {
		t.Fatal("fixture is not using the real current authority composition")
	}
	service := *f.service
	service.CurrentAuthority = gate
	// A missing legacy gate makes accidental bearer fallback fail independently
	// of the synthetic session adapter.
	service.Authority = nil
	target := value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
	parent, cancel := context.WithCancel(ctx)
	defer cancel()
	newOperation := func(interval time.Duration) (*evidence.WorkerEnrollmentOperation, time.Time) {
		current, until := browserCurrentForWorkerTest(t, parent, gate, interval)
		op, err := evidence.NewCurrentWorkerEnrollmentOperation(parent, service, func(tokens evidence.DownloadPeerToken) (evidence.WorkerEnrollmentProofReader, error) {
			return channelSQLProof{tokens, w}, nil
		}, current, target, w.Intent.Authority.Scope)
		if err != nil {
			t.Fatal(err)
		}
		return op, until
	}
	registry := &notifyingWorkerRegistry{source: f.bindings, entered: make(chan struct{})}
	router, err := evidence.NewWorkerEnrollmentRouter(parent, target.InstallationID, registry, time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	first, until := newOperation(time.Second)
	lock, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(context.Background())
	// ReadDownloadWorkerEnrollment is a passive SELECT; an exclusive fixture
	// table lock makes the real SQL read wait without changing any source facts.
	if _, err = lock.Exec(ctx, "LOCK TABLE download_worker IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		route *evidence.WorkerEnrollmentRoute
		err   error
	}
	done := make(chan outcome, 1)
	go func() { r, e := router.Register(parent, first); done <- outcome{r, e} }()
	joined := false
	defer func() {
		if !joined {
			cancel()
			_ = lock.Rollback(context.Background())
			select {
			case got := <-done:
				if got.route != nil {
					got.route.Close()
				}
			case <-time.After(2 * time.Second):
				t.Error("SQL-bound registration did not join during cleanup")
			}
		}
	}()
	select {
	case <-registry.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("registration did not reach the actual SQL reader")
	}
	timer := time.NewTimer(time.Until(until.Add(50 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err = lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		joined = true
		if got.err == nil || got.route != nil {
			if got.route != nil {
				got.route.Close()
			}
			t.Fatal("SQL wait renewed the original browser request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expired SQL-bound registration did not finish")
	}
	if f.issuer.calls.Load() != 0 {
		t.Fatal("expired route issued a certificate")
	}
	if stale, err := router.Register(parent, first); err == nil {
		stale.Close()
		t.Fatal("expired operation restarted itself")
	}
	// A separate live request may resume the same admitted worker. It does not
	// recreate the Job, change the original session or replenish signing slots.
	next, _ := newOperation(5 * time.Second)
	route, err := router.Register(parent, next)
	if err != nil {
		t.Fatal("fresh request could not attach to the admitted worker", err)
	}
	defer route.Close()
	handler, err := workertransport.NewHandler(target.InstallationID, router, time.Now, 1)
	if err != nil {
		t.Fatal(err)
	}
	server, roots := channelServer(t, handler)
	issuerRoots := x509.NewCertPool()
	issuerRoots.AddCert(f.issuer.ca)
	client, err := mtls.NewWorkerCredentials(server.URL, target, roots, issuerRoots, newWorkerChannelFixture(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Enroll(ctx); err != nil {
		t.Fatal("typed browser request did not authorize certificate enrollment over TLS", err)
	}
	peer, err := client.Peer()
	if err != nil || !peer.Valid(time.Now()) || peer.Role != "acquisition" || peer.PeerID != w.Binding.PodUID || f.issuer.calls.Load() != 1 {
		t.Fatal("wrong or repeated acquisition certificate", err)
	}
	registered, err := f.bindings.ReadDownloadWorkerIdentity(ctx, w.Intent.SessionID, peer)
	if err != nil || registered.Worker != w {
		t.Fatal("certificate activation did not preserve admitted worker", err)
	}
	if err = client.Enroll(ctx); err != nil || f.issuer.calls.Load() != 1 {
		t.Fatal("same process key repeated certificate signing", err)
	}
	cancel()
	if _, err = router.BeginWorkerEnrollment(ctx, target.InstallationID, target.SessionID, target.WorkerID, []byte("synthetic.first.token"), f.csr); err == nil {
		t.Fatal("cancelled browser owner retained certificate authority")
	}
}
