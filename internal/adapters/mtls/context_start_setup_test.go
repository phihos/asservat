package mtls

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	execution "asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"golang.org/x/time/rate"
)

// The native setup producer is synthetic here. The socket, process-owned key,
// TLS1.3/H2 exchange and both OwnerAuthenticator calls use the actual adapters.
// Kubernetes proof/generation enforcement is tested in the producer package.
type contextStartSetupFixture struct {
	f                        *contextStartTLSFixture
	begins, full             atomic.Int32
	reads, sources, finishes atomic.Int32
	closes                   atomic.Int32
	fullWork                 func(context.Context, int32) error
	setup                    *contextStartSetupHandle
	begin                    func(context.Context) error
	read                     func(context.Context, int32) error
	source                   func(context.Context) error
	finish                   func(context.Context) error
	close                    func()
	nilSetup                 bool
}

type contextStartSetupHandle struct {
	p          *contextStartSetupFixture
	root       context.Context
	process    execution.APIProcessObservation
	owned      ConnectorProcessObservation
	source     value.ConnectorIdentitySource
	until      time.Time
	closed     atomic.Bool
	finished   atomic.Bool
	sourceRead atomic.Bool
}

func newContextStartSetupFixture(t *testing.T) *contextStartSetupFixture {
	f := newContextStartTLSFixture(t)
	p := &contextStartSetupFixture{f: f}
	f.client.process = p
	return p
}

func (p *contextStartSetupFixture) ReadAPIProcess(ctx context.Context) (execution.APIProcessObservation, error) {
	process, _, err := p.ReadAPIProcessConnector(ctx, p.f.credential)
	return process, err
}

func (p *contextStartSetupFixture) ReadAPIProcessConnector(ctx context.Context, credential *ConnectorProcessCredentials) (execution.APIProcessObservation, ConnectorProcessObservation, error) {
	n := p.full.Add(1)
	if credential != p.f.credential {
		return execution.APIProcessObservation{}, ConnectorProcessObservation{}, value.ErrDenied
	}
	if p.fullWork != nil {
		if err := p.fullWork(ctx, n); err != nil {
			return execution.APIProcessObservation{}, ConnectorProcessObservation{}, err
		}
	}
	owned, err := credential.ObserveConnectorProcess(ctx)
	if err != nil {
		return execution.APIProcessObservation{}, ConnectorProcessObservation{}, err
	}
	process, err := p.f.api(ctx)
	return process, owned, err
}

func (p *contextStartSetupFixture) BeginAPIContextSetup(ctx context.Context, credential *ConnectorProcessCredentials) (ContextStartProcessSetup, error) {
	p.begins.Add(1)
	if credential != p.f.credential {
		return nil, value.ErrDenied
	}
	if p.nilSetup {
		return nil, nil
	}
	owned, err := credential.ObserveConnectorProcess(ctx)
	if err != nil {
		return nil, err
	}
	process, err := p.f.api(ctx)
	if err != nil {
		return nil, err
	}
	source, err := p.f.connector.ReadConnectorIdentitySource(ctx)
	if err != nil {
		return nil, err
	}
	until := identity.Earlier(owned.ValidUntil, identity.Earlier(process.ValidUntil, source.Observation.FreshUntil))
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	p.setup = &contextStartSetupHandle{p: p, root: ctx, process: process, owned: owned, source: source, until: until}
	if p.begin != nil {
		err = p.begin(ctx)
	}
	return p.setup, err
}

func (s *contextStartSetupHandle) current(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && s.root.Err() == nil && !s.closed.Load() && time.Now().Before(s.until)
}

func (s *contextStartSetupHandle) ReadAPIProcessConnector(ctx context.Context, credential *ConnectorProcessCredentials) (execution.APIProcessObservation, ConnectorProcessObservation, error) {
	n := s.p.reads.Add(1)
	if s.p.read != nil {
		if err := s.p.read(ctx, n); err != nil {
			return execution.APIProcessObservation{}, ConnectorProcessObservation{}, err
		}
	}
	if credential != s.p.f.credential || !s.current(ctx) {
		return execution.APIProcessObservation{}, ConnectorProcessObservation{}, value.ErrUnavailable
	}
	process, owned := s.process, s.owned
	process.ValidUntil = identity.Earlier(process.ValidUntil, s.until)
	owned.ValidUntil = identity.Earlier(owned.ValidUntil, s.until)
	return process, owned, nil
}

func (s *contextStartSetupHandle) Source(ctx context.Context) (value.ConnectorIdentitySource, error) {
	s.p.sources.Add(1)
	if !s.current(ctx) || !s.sourceRead.CompareAndSwap(false, true) || s.finished.Load() {
		return value.ConnectorIdentitySource{}, value.ErrUnavailable
	}
	if s.p.source != nil {
		if err := s.p.source(ctx); err != nil {
			return value.ConnectorIdentitySource{}, err
		}
	}
	out := s.source
	out.Observation.Profile = out.Observation.Profile.Clone()
	out.Observation.FreshUntil = identity.Earlier(out.Observation.FreshUntil, s.until)
	return out, nil
}

func (s *contextStartSetupHandle) Finish(ctx context.Context) error {
	s.p.finishes.Add(1)
	if !s.current(ctx) || !s.sourceRead.Load() || !s.finished.CompareAndSwap(false, true) {
		return value.ErrUnavailable
	}
	if s.p.finish != nil {
		return s.p.finish(ctx)
	}
	return nil
}

func (s *contextStartSetupHandle) Close() {
	if s.closed.CompareAndSwap(false, true) {
		s.p.closes.Add(1)
		if s.p.close != nil {
			s.p.close()
		}
	}
}

type contextStartSetupOwners struct {
	OwnerPeerAuthenticator
	calls atomic.Int32
	check func(context.Context, int32) error
}

func (o *contextStartSetupOwners) AuthenticateOwner(ctx context.Context, peer app.OwnerPeerConnection) (value.AuthenticatedOwner, error) {
	n := o.calls.Add(1)
	if o.check != nil {
		if err := o.check(ctx, n); err != nil {
			return value.AuthenticatedOwner{}, err
		}
	}
	return o.OwnerPeerAuthenticator.AuthenticateOwner(ctx, peer)
}

func TestContextStartSetupOwnsExactlyOneOpeningAndNeverLaterChecks(t *testing.T) {
	p := newContextStartSetupFixture(t)
	owners := &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners}
	p.f.client.owners = owners
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exchange, err := p.f.client.Open(ctx, p.f.owner)
	if err != nil {
		t.Fatal("owned setup over actual TLS/H2", err)
	}
	defer exchange.Close()
	if p.begins.Load() != 1 || p.full.Load() != 0 || p.sources.Load() != 1 || p.finishes.Load() != 1 || p.closes.Load() != 1 || owners.calls.Load() != 2 {
		t.Fatalf("setup calls begin/full/source/finish/close/owner = %d/%d/%d/%d/%d/%d", p.begins.Load(), p.full.Load(), p.sources.Load(), p.finishes.Load(), p.closes.Load(), owners.calls.Load())
	}
	before := p.reads.Load()
	if receiver, err := exchange.Check(ctx); err != nil || !receiver.Valid(time.Now()) {
		t.Fatal("later full current check", err)
	}
	if p.full.Load() != 1 || p.reads.Load() != before || p.begins.Load() != 1 || owners.calls.Load() != 3 {
		t.Fatal("later exchange check reused the setup handle")
	}
}

func TestContextStartSetupFailuresCloseAndNeverFallBack(t *testing.T) {
	for _, mode := range []string{"nil", "begin", "initial-read", "post-tls-read", "source", "foreign-source", "shorter-source", "finish", "owner-one", "owner-two", "after-owner-two"} {
		t.Run(mode, func(t *testing.T) {
			p := newContextStartSetupFixture(t)
			owners := &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners}
			p.f.client.owners = owners
			switch mode {
			case "nil":
				p.nilSetup = true
			case "begin":
				p.begin = func(context.Context) error { return value.ErrUnavailable }
			case "initial-read", "post-tls-read":
				p.read = func(_ context.Context, n int32) error {
					if (mode == "initial-read" && n == 1) || (mode == "post-tls-read" && n == 2) {
						return value.ErrUnavailable
					}
					return nil
				}
			case "source":
				p.source = func(context.Context) error { return value.ErrUnavailable }
			case "foreign-source":
				p.source = func(context.Context) error {
					p.setup.source.Observation.Profile.Revision.Generation++
					return nil
				}
			case "shorter-source":
				p.source = func(context.Context) error {
					p.setup.source.Observation.FreshUntil = time.Now().Add(50 * time.Millisecond)
					return nil
				}
			case "finish":
				p.finish = func(context.Context) error { return value.ErrUnavailable }
			case "owner-one", "owner-two":
				owners.check = func(_ context.Context, n int32) error {
					if (mode == "owner-one" && n == 1) || (mode == "owner-two" && n == 2) {
						return value.ErrUnavailable
					}
					return nil
				}
			case "after-owner-two":
				p.read = func(context.Context, int32) error {
					if owners.calls.Load() == 2 {
						return value.ErrUnavailable
					}
					return nil
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			exchange, err := p.f.client.Open(ctx, p.f.owner)
			if exchange != nil {
				exchange.Close()
			}
			if err == nil || p.full.Load() != 0 || p.begins.Load() != 1 || (mode != "nil" && p.closes.Load() != 1) {
				t.Fatal("failed setup escaped, fell back or lost its owner", err, p.full.Load(), p.begins.Load(), p.closes.Load())
			}
			p.f.client.mu.Lock()
			active := len(p.f.client.active)
			p.f.client.mu.Unlock()
			if active != 0 {
				t.Fatal("failed setup retained the transport slot")
			}
		})
	}
}

func TestContextStartSetupShorterFinishBoundsBlockingOwner(t *testing.T) {
	p := newContextStartSetupFixture(t)
	p.finish = func(context.Context) error {
		p.setup.until = time.Now().Add(50 * time.Millisecond)
		return nil
	}
	var end time.Time
	p.f.client.owners = &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners, check: func(ctx context.Context, n int32) error {
		if n == 2 {
			end, _ = ctx.Deadline()
			<-ctx.Done()
		}
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	exchange, err := p.f.client.Open(ctx, p.f.owner)
	if exchange != nil {
		exchange.Close()
	}
	if err == nil || end.IsZero() || end.After(p.setup.until) || time.Since(started) > time.Second || p.closes.Load() != 1 {
		t.Fatal("blocking owner escaped the shortened closing proof", err, end, p.setup.until)
	}
}

func TestContextStartSetupFinalOwnerAndJoinedCloseKeepOriginalCutoff(t *testing.T) {
	for _, mode := range []string{"finish-cancel", "owner-cancel", "owner-expire", "close-cancel", "close-expire"} {
		t.Run(mode, func(t *testing.T) {
			p := newContextStartSetupFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var lateClock atomic.Int64
			p.f.client.now = func() time.Time {
				if at := lateClock.Load(); at != 0 {
					return time.Unix(0, at)
				}
				return time.Now()
			}
			late := func() {
				if mode == "owner-expire" || mode == "close-expire" {
					// Preserve the actual socket deadline while advancing only the
					// transport clock past the original proof interval.
					lateClock.Store(p.setup.until.Add(time.Nanosecond).UnixNano())
				} else {
					cancel()
				}
			}
			switch mode {
			case "finish-cancel":
				p.finish = func(context.Context) error { late(); return nil }
			case "owner-cancel", "owner-expire":
				p.f.client.owners = &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners, check: func(_ context.Context, n int32) error {
					if n == 2 {
						late()
					}
					return nil
				}}
			default:
				p.close = late
			}
			exchange, err := p.f.client.Open(ctx, p.f.owner)
			if exchange != nil {
				exchange.Close()
			}
			if err == nil || p.closes.Load() != 1 {
				t.Fatal("late positive result survived original expiry/cancellation or lost joined close", err, p.closes.Load())
			}
		})
	}
}

func TestContextStartSetupCloseJoinsBeforeOpenReturnsOrReleasesItsSlot(t *testing.T) {
	p := newContextStartSetupFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseOwner := func() { releaseOnce.Do(func() { close(release) }) }
	p.close = func() { close(entered); <-release }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		exchange, err := p.f.client.Open(ctx, p.f.owner)
		if exchange != nil {
			exchange.Close()
		}
		returned <- err
	}()
	select {
	case <-entered:
	case err := <-returned:
		t.Fatal("Open returned without joining its setup owner", err)
	case <-time.After(3 * time.Second):
		t.Fatal("setup did not reach Close")
	}
	// Always release the blocked owner, including assertion failures.
	defer releaseOwner()
	if next, err := p.f.client.Open(ctx, p.f.owner); err == nil || next != nil || p.begins.Load() != 1 {
		t.Fatal("opening slot released before setup joined")
	}
	cancel()
	select {
	case <-returned:
		t.Fatal("cancelled Open returned before Close joined")
	case <-time.After(20 * time.Millisecond):
	}
	releaseOwner()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("Open returned positive after cancellation during joined Close")
		}
	case <-time.After(time.Second):
		t.Fatal("setup close did not release the cancelled opening")
	}
}

func TestContextStartSetupActualHTTP2UnderOriginalNativeLimiterModel(t *testing.T) {
	p := newContextStartSetupFixture(t)
	observer, probe := rate.NewLimiter(20, 20), rate.NewLimiter(20, 20)
	var observerCalls, probeCalls atomic.Int32
	work := func(ctx context.Context, observers, probes int) error {
		for range observers {
			if err := observer.Wait(ctx); err != nil {
				return err
			}
			observerCalls.Add(1)
		}
		for range probes {
			if err := probe.Wait(ctx); err != nil {
				return err
			}
			probeCalls.Add(1)
		}
		return nil
	}
	// Static no-conflict arithmetic with the two installed approved inputs:
	// Begin 83+2 observer /21 probe, Finish 27+2 observer /3 probe. Separate
	// clients retain their actual default 20 QPS/burst20 limits. This explicit
	// synthetic model excludes API latency/concurrent traffic and is NOT native
	// setup qualification; both real fixture owner authentications remain.
	p.begin = func(ctx context.Context) error { return work(ctx, 85, 21) }
	p.finish = func(ctx context.Context) error { return work(ctx, 29, 3) }
	// The old path makes a cold proof then repeats ordinary current proofs.
	// The second proof alone exhausts the original setup interval in this
	// model; its own four sources plus native recheck cost 56+13+2 observer.
	p.fullWork = func(ctx context.Context, n int32) error {
		if n == 1 {
			return work(ctx, 85, 21)
		}
		return work(ctx, 71, 12)
	}
	owners := &contextStartSetupOwners{OwnerPeerAuthenticator: p.f.owners}
	p.f.client.owners = owners
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Start this synthetic source observation at the actual opening, not at
	// the unrelated TLS certificate fixture's whole-second creation time.
	// The clock remains fixed thereafter; no observation is refreshed in flight.
	p.f.connector.advance.Store(int64(time.Since(p.f.connector.now)))
	started := time.Now()
	exchange, err := p.f.client.Open(ctx, p.f.owner)
	if err != nil {
		t.Fatal("complete opening exhausted the original five-second setup interval", err)
	}
	defer exchange.Close()
	if observerCalls.Load() != 114 || probeCalls.Load() != 24 || p.begins.Load() != 1 || p.full.Load() != 0 || owners.calls.Load() != 2 || p.closes.Load() != 1 || !time.Now().Before(started.Add(5*time.Second)) {
		t.Fatal("limiter model changed or setup renewed", observerCalls.Load(), probeCalls.Load(), p.full.Load(), owners.calls.Load())
	}
	t.Logf("synthetic complete opening: observer=%d probe=%d owner=%d elapsed=%s", observerCalls.Load(), probeCalls.Load(), owners.calls.Load(), time.Since(started).Round(time.Millisecond))
}
