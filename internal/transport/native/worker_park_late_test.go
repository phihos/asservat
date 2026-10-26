package native_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	native "asservat.local/asservat/internal/transport/native"
)

// native83 follow-up: the operation is published shortly before the parked
// request's park window ends, and its conversation then runs well past both
// that window and the worker's five-second request setup bound, while the
// operation lease is still current. The attached conversation must be bounded
// by the operation (and its per-frame checks), never by the idle lookup.
func TestHubWorkerLatePublishedConversationOutlivesParkWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
	// The idle observation ends 5 s after now; the park window 2 s earlier.
	parkEnd := peers.idle.Until.Add(-2 * time.Second)
	serving := &hubWorkerServing{until: time.Now().Add(14 * time.Second), pod: nativeID}
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
	attached := make(chan *native.HubOperation, 1)
	go func() {
		time.Sleep(time.Until(parkEnd.Add(-400 * time.Millisecond)))
		origin, _, factory := routerFixtureFor(t, 5*time.Second, nil)
		registration, err := router.Register(ctx, origin.Lease.Operation, factory)
		if err != nil {
			attached <- nil
			return
		}
		defer registration.Close()
		peers.origin = origin
		peers.published.Store(true)
		operation, err := registration.Wait(ctx)
		if err != nil {
			operation = nil
		}
		attached <- operation
		<-ctx.Done()
	}()
	started := time.Now()
	stream, err := client.Open(ctx, workerHello())
	if err != nil || stream == nil {
		t.Fatal("the late published operation was not attached", err, time.Since(started))
	}
	defer stream.Close()
	var operation *native.HubOperation
	select {
	case operation = <-attached:
	case <-ctx.Done():
	}
	if operation == nil {
		t.Fatal("owner did not observe the attachment")
	}
	// The worker's read takes longer than what remained of the park window
	// and of the worker's request setup bound.
	time.Sleep(time.Until(started.Add(6500 * time.Millisecond)))
	if stream.Context().Err() != nil || operation.Context().Err() != nil {
		t.Fatal("the attached conversation ended with the idle lookup, not its operation", stream.Context().Err(), operation.Context().Err())
	}
	if _, err := operation.Gate().Check(ctx); err != nil {
		t.Fatal("operation gate ended with the idle lookup", err)
	}
	receive, stopReceive := context.WithTimeout(ctx, 2*time.Second)
	f, err := stream.Receive(receive)
	stopReceive()
	clear(f.Payload)
	if err != nil || f.Kind != contracts.NativeCommandFrame {
		t.Fatal("the attached conversation did not survive past the park window", err)
	}
}
