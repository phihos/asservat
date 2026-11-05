package bootstrap

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
)

type browserCleanupSource struct {
	fail, suspended bool
	reads           atomic.Int32
	second          func()
}

func (s *browserCleanupSource) BrowserSettings(context.Context) (identity.BrowserSettings, error) {
	if s.reads.Add(1) == 2 && s.second != nil {
		s.second()
	}
	n := time.Now()
	a := identity.BrowserSettings{RootID: runtimeID, Epoch: runtimeID, Issuer: "https://id.example.test", ClientID: "console", Origin: "https://console.example.test", Revision: identity.Revision{UID: "settings", Generation: 1, Digest: [32]byte{1}}, MaxLifetimeSeconds: 3600, MaxLogins: 10, MaxSessions: 10, MaxLogoutEvents: 10, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Suspended: s.suspended}
	if s.fail {
		return a, identity.ErrUnavailable
	}
	return a, nil
}

type browserCleanupProjection struct{ observed, fenced int }

func (p *browserCleanupProjection) ObserveBrowserSettings(context.Context, identity.BrowserSettings) error {
	p.observed++
	return nil
}
func (p *browserCleanupProjection) FenceBrowserSettings(context.Context, time.Time) error {
	p.fenced++
	return nil
}

type browserCleanupFunc func(context.Context) error

func (f browserCleanupFunc) Cleanup(ctx context.Context) error { return f(ctx) }

func TestBrowserWorkerCleanupIndependentOfSettingsAndRateBounded(t *testing.T) {
	for _, mode := range []string{"current", "suspended", "source-outage"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			source := &browserCleanupSource{fail: mode == "source-outage", suspended: mode == "suspended", second: cancel}
			projection := &browserCleanupProjection{}
			calls := 0
			p := permissionWorker{browser: &identities.BrowserSettingsObserver{Source: source, Projection: projection, Now: time.Now}, browserCleanup: browserCleanupFunc(func(call context.Context) error {
				calls++
				if call.Err() != nil {
					t.Error("cleanup started after cancellation")
				}
				end, ok := call.Deadline()
				if !ok || time.Until(end) > time.Second || time.Until(end) <= 0 {
					t.Error("cleanup lacks original one-second bound")
				}
				// A failed prune is reported, not retried on every settings iteration.
				return identity.ErrUnavailable
			})}
			p.runBrowserSettings(ctx)
			if source.reads.Load() != 2 || calls != 1 {
				t.Fatalf("settings cadence blocked or cleanup repeated: reads=%d prune=%d", source.reads.Load(), calls)
			}
			if mode == "source-outage" && projection.fenced < 1 || mode != "source-outage" && projection.observed < 1 {
				t.Fatal("settings behavior changed")
			}
		})
	}
}
func TestBrowserWorkerCleanupJoinsOwningCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, joined, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	source := &browserCleanupSource{}
	p := permissionWorker{browser: &identities.BrowserSettingsObserver{Source: source, Projection: &browserCleanupProjection{}, Now: time.Now}, browserCleanup: browserCleanupFunc(func(call context.Context) error {
		close(entered)
		<-call.Done()
		<-release
		close(joined)
		return call.Err()
	})}
	go func() { p.runBrowserSettings(ctx); close(done) }()
	<-entered
	cancel()
	select {
	case <-done:
		t.Fatal("worker returned before SQL child joined")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not join")
	}
	select {
	case <-joined:
	default:
		t.Fatal("unjoined cleanup")
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("owner cancellation changed")
	}
}
