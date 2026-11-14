package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	apps "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes"
)

// This fixed fixture continuation borrows the actual still-live predecessor.
// It is never supplied to a product constructor as authority or a callback.
type initialRuntimeOwnerContinuation struct {
	resources *kube.InitialRuntimeResources
	bridge    *kube.InitialRuntimeBridge
	original  *apps.Deployment
}

// The enclosing worker owns this cleanup, registered before qualify can launch
// an owner. Keep its Deployment present through the worker's later source-loss
// assertions so owner deletion cannot become a different guard-loss trigger.
func (o *initialRuntimeOwnerContinuation) cleanup(t *testing.T, api kubernetes.Interface) {
	if o != nil && o.original != nil {
		providerWorkerNativeCleanup(t, api, o.original)
	}
}

func providerOwnerScopedPool(t *testing.T, ctx context.Context, config *pgx.ConnConfig, credential contracts.OwnerSQLCredential) *pgxpool.Pool {
	t.Helper()
	if credential.Username == "" || credential.Password == "" {
		t.Fatal("original scoped credential missing")
	}
	p, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	p.ConnConfig = config.Copy()
	p.ConnConfig.User, p.ConnConfig.Password = credential.Username, credential.Password
	p.ConnConfig.RuntimeParams = map[string]string{"application_name": "asservat-original-owner-native-observer", "statement_timeout": "5000ms", "lock_timeout": "1000ms", "idle_in_transaction_session_timeout": "5000ms"}
	p.MaxConns, p.MinConns = contracts.OwnerIdentityPoolConnections, 0
	pool, err := pgxpool.NewWithConfig(ctx, p)
	if err != nil {
		t.Fatal("original scoped observer connection", err)
	}
	return pool
}

// Counts and original request-deadline minima are diagnostics only. This fixed
// six-client recorder sees neither paths, headers nor bodies, performs no I/O,
// and does not create a context or a limiter. At most four nested named phases
// are retained; memory does not grow with request count.
type nativeOwnerDeadlineTrace struct {
	mu      sync.Mutex
	enabled bool
	phases  [4]*nativeOwnerDeadlinePhase
}
type nativeOwnerDeadlinePhase struct {
	name                    string
	calls, missing, expired [6]int64
	before, after           [6]time.Duration
}

func (x *nativeOwnerDeadlineTrace) enable() { x.mu.Lock(); x.enabled = true; x.mu.Unlock() }
func (x *nativeOwnerDeadlineTrace) begin(name string) func(*testing.T) {
	x.mu.Lock()
	if !x.enabled {
		x.mu.Unlock()
		return func(*testing.T) {}
	}
	p := &nativeOwnerDeadlinePhase{name: name}
	slot := -1
	for i, old := range x.phases {
		if old == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		x.mu.Unlock()
		return func(t *testing.T) { t.Error("owner trace phase bound exceeded") }
	}
	x.phases[slot] = p
	x.mu.Unlock()
	return func(t *testing.T) {
		x.mu.Lock()
		copy := *p
		x.phases[slot] = nil
		x.mu.Unlock()
		t.Logf("native original-deadline phase=%s calls=%v missing=%v expired-at-return=%v minimum-before[C B H S W T]=%v minimum-after=%v; no deadline created or renewed", copy.name, copy.calls, copy.missing, copy.expired, copy.before, copy.after)
	}
}
func (x *nativeOwnerDeadlineTrace) request(client int, ctx context.Context) func() {
	x.mu.Lock()
	if !x.enabled {
		x.mu.Unlock()
		return func() {}
	}
	phases := x.phases
	deadline, ok := ctx.Deadline()
	remaining := time.Until(deadline)
	for _, p := range phases {
		if p == nil {
			continue
		}
		p.calls[client]++
		if !ok {
			p.missing[client]++
			continue
		}
		if p.calls[client] == 1 || remaining < p.before[client] {
			p.before[client] = remaining
		}
	}
	x.mu.Unlock()
	return func() {
		x.mu.Lock()
		defer x.mu.Unlock()
		remaining := time.Until(deadline)
		for _, p := range phases {
			if p == nil || !ok {
				continue
			}
			if p.after[client] == 0 || remaining < p.after[client] {
				p.after[client] = remaining
			}
			if remaining <= 0 || ctx.Err() != nil {
				p.expired[client]++
			}
		}
	}
}

func initialBootstrapFixtureDuration(owner bool) time.Duration {
	if owner {
		return 12 * time.Minute
	}
	return 8 * time.Minute
}
func TestInitialBootstrapAggregateDeadlineSelection(t *testing.T) {
	if initialBootstrapFixtureDuration(false) != 8*time.Minute || initialBootstrapFixtureDuration(true) != 12*time.Minute {
		t.Fatal("owner-only aggregate fixture budget changed legacy or product selection")
	}
}
