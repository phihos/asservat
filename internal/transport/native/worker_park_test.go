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
func (p *parkPeers) RecheckWorkerNative(_ context.Context, _ *tls.ConnectionState, origin evidence.NativeOrigin) (value.NativeLease, error) {
	return origin.Lease, nil
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
func TestHubWorkerParkedRequestAttachesLaterPublishedOperation(t *testing.T) {
	for _, mode := range []string{"published", "unpublished"} {
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
			go func() { served <- native.Serve(serveCtx, listener, roots, syntheticServingCertificate{cert}, handler, 1) }()
			defer func() { stopServe(); <-served }()
			client, err := mtls.NewNativeClient("https://"+listener.Addr().String()+contracts.NativeWorkerPath, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
			if err != nil {
				t.Fatal(err)
			}

			// The human request claims and publishes its operation while the
			// worker's request is already waiting at the hub.
			attached := make(chan *native.HubOperation, 1)
			if mode == "published" {
				go func() {
					time.Sleep(700 * time.Millisecond)
					origin, _, factory := routerFixture(t)
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
