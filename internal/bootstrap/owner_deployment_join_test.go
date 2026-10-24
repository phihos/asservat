package bootstrap

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

type ownerDeploymentJoinProof struct {
	entered   chan context.Context
	cancelled chan struct{}
	release   chan struct{}
}

func (p *ownerDeploymentJoinProof) ReadOwnerEnrollmentProof(ctx context.Context, _ value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error) {
	p.entered <- ctx
	<-ctx.Done()
	close(p.cancelled)
	<-p.release
	return value.OwnerEnrollmentProof{}, ctx.Err()
}

func ownerDeploymentJoinFixture(t *testing.T, closeResource func()) (*OwnerDeployment, *ownerDeploymentJoinProof, *runtimeFixture, net.Listener, string) {
	t.Helper()
	f, config, listener := newRuntimeFixture(t)
	proof := &ownerDeploymentJoinProof{entered: make(chan context.Context, 1), cancelled: make(chan struct{}), release: make(chan struct{})}
	config.Proofs = proof
	root, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime, err := NewOwnerRuntime(root, config)
	if err != nil {
		t.Fatal(err)
	}
	inputs, directory, _ := ownerInputFixture(t)
	writeOwnerJSON(t, directory, "worker-controls.json", contracts.OwnerWorkerTrust{Format: contracts.OwnerWorkerTrustFormat, Controls: [][]byte{}})
	trust, err := mtls.NewWorkerTrustCatalog(runtimeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &OwnerDeployment{Runtime: runtime, inputs: inputs, trust: trust, root: root, cancel: cancel, closers: []func(){closeResource}}
	return d, proof, f, listener, directory
}

func TestOwnerDeploymentExternalCloseJoinsRuntimeBeforeDependencies(t *testing.T) {
	resources := make(chan struct{})
	var calls atomic.Int32
	d, proof, _, listener, _ := ownerDeploymentJoinFixture(t, func() { calls.Add(1); close(resources) })
	var once sync.Once
	release := func() { once.Do(func() { close(proof.release) }) }
	runDone := make(chan struct{})
	var result error
	go func() { result = d.Run(listener); close(runDone) }()
	defer func() { release(); d.Close(); <-runDone }()
	var original context.Context
	select {
	case original = <-proof.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("legacy readiness did not enter native proof")
	}
	until, ok := original.Deadline()
	if !ok || time.Until(until) > 5*time.Second {
		t.Fatal("readiness lost its original bound")
	}
	closed := make(chan struct{}, 2)
	for range 2 {
		go func() { d.Close(); closed <- struct{}{} }()
	}
	select {
	case <-proof.cancelled:
	case <-time.After(time.Second):
		t.Fatal("external Close did not cancel native proof")
	}
	select {
	case <-closed:
		t.Error("legacy Close returned before the admitted Runtime joined")
		closed <- struct{}{} // retain both completions for explicit cleanup
	case <-resources:
		t.Error("legacy dependencies closed while readiness retained them")
	case <-time.After(100 * time.Millisecond):
	}
	if d.Runtime.Ready() || d.Run(listener) == nil {
		t.Error("closing deployment retained readiness or accepted another Run")
	}
	if _, _, err := d.Runtime.server.ReadinessRequest(); err == nil {
		t.Error("closing deployment retained serving key authority")
	}
	if got, _ := original.Deadline(); !got.Equal(until) {
		t.Error("shutdown extended the original native deadline")
	}
	release()
	select {
	case <-runDone:
		if !errors.Is(result, context.Canceled) {
			t.Error("legacy Run lost original cancellation", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("released legacy Runtime did not join")
	}
	for range 2 {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close did not join")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent shutdown closed dependencies more than once")
	}
}

func TestOwnerDeploymentDeferredCloseJoinsWithoutSelfWait(t *testing.T) {
	for _, mode := range []string{"parent-cancel", "catalog-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			d, proof, _, listener, directory := ownerDeploymentJoinFixture(t, func() { calls.Add(1) })
			var once sync.Once
			release := func() { once.Do(func() { close(proof.release) }) }
			done := make(chan struct{})
			var result error
			go func() { result = d.Run(listener); close(done) }()
			defer func() { release(); d.Close(); <-done }()
			select {
			case <-proof.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("legacy readiness did not enter")
			}
			if mode == "parent-cancel" {
				d.cancel()
			} else if err := os.Remove(filepath.Join(directory, "worker-controls.json")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-proof.cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("stop condition did not cancel readiness")
			}
			select {
			case <-done:
				t.Error("Run detached readiness before deferred shutdown")
			case <-time.After(100 * time.Millisecond):
			}
			if calls.Load() != 0 {
				t.Error("Run released resources while native child remained owned")
			}
			release()
			select {
			case <-done:
				if result == nil || mode == "parent-cancel" && !errors.Is(result, context.Canceled) || calls.Load() != 1 {
					t.Error("Run lost error or joined dependency closure", result)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("deferred Close waited for its own Run registration")
			}
		})
	}
}

func TestOwnerDeploymentCloseBeforeRunRejectsAnyRuntimeAdmission(t *testing.T) {
	var calls atomic.Int32
	d, _, f, listener, _ := ownerDeploymentJoinFixture(t, func() { calls.Add(1) })
	d.Close()
	if d.Run(listener) == nil {
		t.Fatal("closed legacy deployment accepted Run")
	}
	d.Close()
	if d.Runtime.started.Load() || f.signings.Load() != 0 || calls.Load() != 1 {
		t.Fatal("closed legacy deployment entered Runtime or repeated resource close")
	}
}
