package evidence

import (
	"context"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

func TestWorkerRoutesCloseAndJoinRetainsRegistrationIO(t *testing.T) {
	router, operations := routeTestSetup(t, 1, 1)
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	router.bindings = routeBindingsFunc(func(ctx context.Context, _, _ string) (value.DownloadWorkerIdentity, error) {
		entered <- ctx
		<-release
		return value.DownloadWorkerIdentity{}, ctx.Err()
	})
	registered := make(chan struct{})
	var result error
	go func() {
		h, err := router.Register(context.Background(), operations[0])
		if h != nil {
			h.Close()
		}
		result = err
		close(registered)
	}()
	defer func() { finish(); <-registered; router.CloseAndJoin() }()
	var original context.Context
	select {
	case original = <-entered:
	case <-time.After(time.Second):
		t.Fatal("registration did not reach original binding read")
	}
	closed := make(chan struct{})
	go func() { router.CloseAndJoin(); close(closed) }()
	defer func() { finish(); <-closed }()
	select {
	case <-original.Done():
	case <-time.After(time.Second):
		t.Fatal("router closure did not cancel registration")
	}
	select {
	case <-closed:
		t.Error("router join returned with registration I/O still active")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := router.Register(context.Background(), operations[0]); err == nil {
		t.Error("closing router admitted another registration")
	}
	finish()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("released registration did not join")
	}
	<-registered
	if result == nil {
		t.Fatal("cancelled registration succeeded")
	}
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.used != 0 || len(router.entries) != 0 {
		t.Fatal("joined registration retained a slot or route")
	}
}

func TestWorkerRoutesCloseAndJoinRetainsBusyEnrollment(t *testing.T) {
	router, operations := routeTestSetup(t, 1, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	operations[0].proofs = func(DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
		close(entered)
		<-release
		return nil, artifact.ErrDownloadUnavailable
	}
	route, err := router.Register(context.Background(), operations[0])
	if err != nil {
		t.Fatal(err)
	}
	enrollment := make(chan struct{})
	go func() {
		v := operations[0].target
		delivery, err := router.BeginWorkerEnrollment(context.Background(), v.InstallationID, v.SessionID, v.WorkerID, []byte("synthetic-token"), []byte("synthetic-csr"))
		if delivery != nil {
			delivery.Close()
		}
		if err == nil {
			t.Error("cancelled routed proof succeeded")
		}
		close(enrollment)
	}()
	defer func() { finish(); <-enrollment; router.CloseAndJoin() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("routed enrollment did not enter original proof")
	}
	closed := make(chan struct{})
	go func() { router.CloseAndJoin(); close(closed) }()
	defer func() { finish(); <-closed }()
	select {
	case <-route.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("router shutdown did not cancel the busy route")
	}
	select {
	case <-closed:
		t.Error("router join returned before its busy enrollment released")
	case <-time.After(50 * time.Millisecond):
	}
	router.mu.Lock()
	retained := router.used == 1 && route.busy && !route.released && route.op != nil
	router.mu.Unlock()
	if !retained {
		t.Error("closing enrollment lost its charged slot before completion")
	}
	finish()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("released enrollment did not join")
	}
	<-enrollment
	router.mu.Lock()
	defer router.mu.Unlock()
	if router.used != 0 || !route.released || route.op != nil {
		t.Fatal("joined enrollment retained its credential owner")
	}
}
