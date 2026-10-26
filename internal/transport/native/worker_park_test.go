package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

// parkPeers answers the worker check as the SQL locator would: idle until the
// operation's owner has published it, then the exact stored operation.
type parkPeers struct {
	origin    evidence.NativeOrigin
	idle      *evidence.NativeIdle
	published atomic.Bool
	checks    atomic.Int32
	origins   *evidence.NativeOrigins
}

func (p *parkPeers) CheckWorkerNative(_ context.Context, state *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	p.checks.Add(1)
	if state == nil || len(state.PeerCertificates) < 1 || h.Reference != workerHello().Reference {
		return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
	}
	if !p.published.Load() {
		idle := *p.idle
		return evidence.NativeOrigin{}, &idle
	}
	return p.origin, nil
}
func (p *parkPeers) CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
}
func (p *parkPeers) RecheckWorkerNative(ctx context.Context, _ *tls.ConnectionState, origin evidence.NativeOrigin) (value.NativeLease, error) {
	if p.origins != nil {
		return p.origins.Recheck(ctx, origin)
	}
	return origin.Lease, nil
}

// slowOperations is the hub's operation observation with an installed cost:
// one fenced SQL transaction took about 0.2 s in native78/79.
type slowOperations struct {
	lease atomic.Pointer[value.NativeLease]
	reads atomic.Int32
}

func (s *slowOperations) ObserveNativeOperation(ctx context.Context, ref value.NativeReference, _ value.KeyPeer) (value.NativeLease, error) {
	s.reads.Add(1)
	l := s.lease.Load()
	if l == nil || ref != l.Operation.Reference {
		return value.NativeLease{}, contracts.ErrNativeProtocol
	}
	select {
	case <-time.After(250 * time.Millisecond):
		return *l, nil
	case <-ctx.Done():
		return value.NativeLease{}, ctx.Err()
	}
}
func (p *parkPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return value.NativeLease{}, contracts.ErrNativeProtocol
}

// The worker's single native request reaches the hub before the human request
// has claimed its operation. Previously the hub answered idle at once and the
// worker's next lookup followed only after its retry interval, so the claim
// and the worker's schedule had to coincide inside one short human request.
// The parked request now attaches as soon as the owner publishes the
// operation. Worker/SQL authority is synthetic; the production handler,
// HubWorkerAdmission, router, registration, TLS/h2 and NativeClient are real.
//
// "installed-cost" reproduces installed native79: both the worker gate and the
// operation gate recheck through Origins.Recheck, whose operation observation
// takes 250 ms (a fenced SQL transaction there), and the published operation
// has 1.5 s left of its request's authority. Without the bounded recheck
// interval the attachment and nested gates repeated that observation eight
// times between the wake-up and the command frame and the lease ran out
// first (installed native79 died at serve/command; this run at the response).
func TestHubWorkerParkedRequestAttachesLaterPublishedOperation(t *testing.T) {
	for _, mode := range []string{"published", "unpublished", "installed-cost"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cert, clientCert, roots := testCertificates(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			router, err := native.NewHubRouter(1)
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			peers := &parkPeers{idle: syntheticNativeIdle(t)}
			lifetime := 4 * time.Second
			var recheck func(context.Context, evidence.NativeOrigin) (value.NativeLease, error)
			operations := &slowOperations{}
			if mode == "installed-cost" {
				lifetime = 1500 * time.Millisecond
				peers.origins = &evidence.NativeOrigins{Operations: operations, Now: time.Now, Recent: evidence.NewNativeRecentObservations()}
				recheck = peers.origins.Recheck
			}
			serving := &hubWorkerServing{until: time.Now().Add(9 * time.Second), pod: nativeID}
			admission, err := native.NewHubWorkerAdmission(peers, serving, router, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := native.NewHandler(contracts.NativeWorkerPath, listener.Addr().String(), admission, 1)
			if err != nil {
				t.Fatal(err)
			}
			serveCtx, stopServe := context.WithCancel(ctx)
			served := make(chan error, 1)
			go func() {
				served <- native.Serve(serveCtx, listener, roots, syntheticServingCertificate{cert}, handler, 1)
			}()
			defer func() { stopServe(); <-served }()
			client, err := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			if err != nil {
				t.Fatal(err)
			}

			// The human request claims and publishes its operation while the
			// worker's request is already waiting at the hub.
			attached := make(chan *native.HubOperation, 1)
			if mode != "unpublished" {
				go func() {
					time.Sleep(700 * time.Millisecond)
					origin, _, factory := routerFixtureFor(t, lifetime, recheck)
					operations.lease.Store(&origin.Lease)
					registration, err := router.Register(ctx, origin.Lease.Operation, factory)
					if err != nil {
						attached <- nil
						return
					}
					defer registration.Close()
					peers.origin = origin
					peers.published.Store(true)
					operation, err := registration.Wait(ctx)
					attached <- operation
					if err == nil {
						<-ctx.Done()
					}
				}()
			}
			started := time.Now()
			stream, err := client.Open(ctx, workerHello())
			elapsed := time.Since(started)
			if mode == "unpublished" {
				var idle *contracts.NativeNoCommand
				if stream != nil || !errors.As(err, &idle) || !time.Now().Before(idle.Until) || elapsed >= 5*time.Second {
					t.Fatal("an unpublished parked request did not end with a still valid idle", err, elapsed)
				}
				return
			}
			if err != nil || stream == nil {
				t.Fatal("the worker request did not attach the later published operation", err, peers.checks.Load())
			}
			defer stream.Close()
			// The woken conversation is served at once: the worker receives
			// its command on the parked request's own stream.
			receive, stopReceive := context.WithTimeout(ctx, 2*time.Second)
			f, err := stream.Receive(receive)
			stopReceive()
			clear(f.Payload)
			if err != nil || f.Kind != contracts.NativeCommandFrame {
				t.Fatal("the woken worker did not receive its command", err, f.Kind, time.Since(started))
			}
			if n := operations.reads.Load(); mode == "installed-cost" && n > 2 {
				t.Fatal("the gates repeated the operation observation within one recheck interval", n)
			}
			select {
			case operation := <-attached:
				if operation == nil {
					t.Fatal("owner did not observe the attachment")
				}
			case <-ctx.Done():
				t.Fatal("owner wait did not end")
			}
			if peers.checks.Load() != 2 {
				t.Fatal("the woken request did not repeat the complete worker check exactly once", peers.checks.Load())
			}
		})
	}
}

// The shared operation observation is bounded: a revoked operation is refused
// at the first recheck after NativeRecheckInterval, and a failed read is never
// reused.
func TestOriginsRecheckSharesObservationWithinInterval(t *testing.T) {
	origin, _, _ := routerFixtureFor(t, 4*time.Second, nil)
	operations := &slowOperations{}
	operations.lease.Store(&origin.Lease)
	origins := evidence.NativeOrigins{Operations: operations, Now: time.Now, Recent: evidence.NewNativeRecentObservations()}
	ctx := context.Background()
	for range 3 {
		if _, err := origins.Recheck(ctx, origin); err != nil {
			t.Fatal(err)
		}
	}
	if operations.reads.Load() != 1 {
		t.Fatal("rechecks within one interval repeated the observation", operations.reads.Load())
	}
	operations.lease.Store(nil) // e.g. the operation row was revoked
	time.Sleep(evidence.NativeRecheckInterval)
	for range 2 {
		if _, err := origins.Recheck(ctx, origin); err == nil {
			t.Fatal("revocation outlived the recheck interval")
		}
	}
	if operations.reads.Load() != 3 {
		t.Fatal("a failed observation was reused", operations.reads.Load())
	}
}
