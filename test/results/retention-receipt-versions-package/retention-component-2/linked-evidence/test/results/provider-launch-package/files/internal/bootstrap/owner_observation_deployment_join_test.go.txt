package bootstrap

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// This is an existing consumer port, not a production authority substitute.
// A readiness operation retains its original context until explicitly released.
type observationJoinProof struct {
	entered   chan context.Context
	cancelled chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (p *observationJoinProof) ReadOwnerEnrollmentProof(ctx context.Context, _ value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
	p.once.Do(func() { p.entered <- ctx })
	<-ctx.Done()
	close(p.cancelled)
	<-p.release
	return value.OwnerEnrollmentProof{}, ctx.Err()
}

func observationDeploymentJoinFixture(t *testing.T, closed func()) (*OwnerObservationDeployment, *observationJoinProof, net.Listener, *runtimeFixture) {
	t.Helper()
	base, c := observationRuntimeConfig(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	base.configuration.Pool.NativePort = listener.Addr().(*net.TCPAddr).Port
	c.Pin.Pool = base.configuration.Pool
	// Reuse the independently scoped two-SAN test issuer. Real process keys,
	// supervisor and readiness run below; its CA/registry remain synthetic.
	issuer := &observationForwardFixture{t: t, base: base, pin: c.Pin, bound: time.Now().Add(time.Minute), identities: map[value.OwnerCertificate]value.OwnerEnrollment{}}
	c.ServerEnrollment, c.ClientEnrollment, c.Registry = issuer, issuer, issuer
	proof := &observationJoinProof{entered: make(chan context.Context, 1), cancelled: make(chan struct{}), release: make(chan struct{})}
	c.Proofs = proof
	root, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime, err := NewOwnerObservationRuntime(root, c)
	if err != nil {
		t.Fatal(err)
	}
	return &OwnerObservationDeployment{Runtime: runtime, base: &OwnerDeployment{root: root, cancel: cancel, closers: []func(){closed}}}, proof, listener, base
}

func TestOwnerObservationDeploymentExternalCloseJoinsReadinessBeforeDependencies(t *testing.T) {
	var closes atomic.Int32
	resources := make(chan struct{})
	d, proof, listener, _ := observationDeploymentJoinFixture(t, func() { closes.Add(1); close(resources) })
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(proof.release) }) }
	runDone, closeDone := make(chan struct{}), make(chan struct{})
	var result error
	go func() { result = d.Run(listener); close(runDone) }()
	defer func() { release(); d.Close(); <-runDone }()
	var original context.Context
	select {
	case original = <-proof.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual readiness did not enter its native proof read")
	}
	originalUntil, ok := original.Deadline()
	if !ok || time.Until(originalUntil) > 5*time.Second {
		t.Fatal("readiness lost its original five-second bound")
	}
	go func() { d.Close(); close(closeDone) }()
	select {
	case <-proof.cancelled:
	case <-time.After(time.Second):
		t.Fatal("external Close did not cancel readiness")
	}
	select {
	case <-closeDone:
		t.Error("Close returned before the admitted readiness read joined")
	case <-resources:
		t.Error("provider dependencies closed while readiness retained them")
	case <-time.After(100 * time.Millisecond):
	}
	if d.Runtime.Ready() || d.Run(listener) == nil {
		t.Error("closing deployment retained readiness or admitted another Run")
	}
	if _, _, err := d.Runtime.server.ReadinessRequest(); err == nil {
		t.Error("cancelled owner retained serving key authority")
	}
	if until, _ := original.Deadline(); !until.Equal(originalUntil) {
		t.Error("shutdown changed the original readiness deadline")
	}
	release()
	select {
	case <-runDone:
		if !errors.Is(result, context.Canceled) {
			t.Error("Run lost its cancellation result", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not join after proof release")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("external Close did not join after proof release")
	}
	d.Close()
	if closes.Load() != 1 {
		t.Fatal("dependencies were not closed exactly once")
	}
}

func TestOwnerObservationDeploymentRunCancellationJoinsBeforeDeferredClose(t *testing.T) {
	var closes atomic.Int32
	d, proof, listener, _ := observationDeploymentJoinFixture(t, func() { closes.Add(1) })
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(proof.release) }) }
	done := make(chan struct{})
	var result error
	go func() { result = d.Run(listener); close(done) }()
	defer func() { release(); d.Close(); <-done }()
	select {
	case <-proof.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("readiness did not enter")
	}
	d.base.cancel()
	select {
	case <-proof.cancelled:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not reach readiness")
	}
	select {
	case <-done:
		t.Error("Run returned before its child joined")
	case <-time.After(100 * time.Millisecond):
	}
	if closes.Load() != 0 {
		t.Error("deferred shutdown released dependencies before child completion")
	}
	release()
	select {
	case <-done:
		if !errors.Is(result, context.Canceled) || closes.Load() != 1 {
			t.Error("Run did not preserve its result and dependency lifetime", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run's deferred Close waited for its own registration")
	}
}

func TestOwnerObservationDeploymentCloseBeforeRunPreventsEnrollment(t *testing.T) {
	var closes atomic.Int32
	d, _, listener, fixture := observationDeploymentJoinFixture(t, func() { closes.Add(1) })
	d.Close()
	if d.Run(listener) == nil {
		t.Fatal("closed deployment accepted Run")
	}
	d.Close()
	if d.Runtime.started.Load() || fixture.signings.Load() != 0 || closes.Load() != 1 {
		t.Fatal("closed deployment admitted work or released dependencies twice")
	}
}
