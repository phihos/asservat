package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
)

type hubWorkerJoinTransport func(*http.Request) (*http.Response, error)

func (f hubWorkerJoinTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func hubWorkerJoinFixture(t *testing.T, transport http.RoundTripper, closeResource func()) *HubWorkerDeployment {
	t.Helper()
	client, err := kube.NewPermissionClient(&rest.Config{Host: "https://worker-join.invalid", Transport: transport},
		"c362d644-49ca-46ce-b1e7-a20000000001", cfg.NamespaceRef{Name: "owners", UID: "c362d644-49ca-46ce-b1e7-a20000000002"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := kube.NewReconciliationLeader(client, "configuration", "c362d644-49ca-46ce-b1e7-a20000000003", "c362d644-49ca-46ce-b1e7-a20000000004")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The actual leader's first namespace GET blocks before any observation or
	// lease effect. Empty reconciliation dependencies are never invoked.
	return &HubWorkerDeployment{root: ctx, cancel: cancel, leader: leader, reconciler: &app.ConfigurationReconciler{}, closers: []func(){closeResource}}
}

func TestHubWorkerExternalCloseJoinsRunBeforeClosingResources(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	resourceClosed := make(chan struct{})
	var closedCalls atomic.Int32
	d := hubWorkerJoinFixture(t, hubWorkerJoinTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/owners" {
			t.Errorf("unexpected leader read: %s %s", r.Method, r.URL.Path)
		}
		close(entered)
		<-r.Context().Done()
		close(cancelled)
		// Deliberately retain this cancelled call's resources until joined.
		<-release
		return nil, r.Context().Err()
	}), func() { closedCalls.Add(1); close(resourceClosed) })
	joined, closeDone := make(chan struct{}), make(chan struct{})
	var result error
	go func() { result = d.Run(); close(joined) }()
	defer func() {
		unblock()
		d.Close()
		select {
		case <-joined:
		case <-time.After(2 * time.Second):
			t.Error("released leader did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not enter read")
	}
	go func() { d.Close(); close(closeDone) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel active leader read")
	}
	select {
	case <-closeDone:
		t.Error("Close returned with a leader read still active")
	case <-resourceClosed:
		t.Error("Close released a provider before its active Run joined")
	case <-time.After(100 * time.Millisecond):
	}
	if err := d.Run(); err == nil {
		t.Error("closing deployment accepted another Run")
	}
	unblock()
	select {
	case <-joined:
		if !errors.Is(result, context.Canceled) {
			t.Errorf("Run result = %v; want original cancellation", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not join after released read")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("external Close did not join")
	}
	d.Close()
	if closedCalls.Load() != 1 {
		t.Fatal("provider ownership closed more than once")
	}
}

func TestHubWorkerCloseBeforeRunPreventsAnyLeaderRead(t *testing.T) {
	var reads, closed atomic.Int32
	d := hubWorkerJoinFixture(t, hubWorkerJoinTransport(func(*http.Request) (*http.Response, error) {
		reads.Add(1)
		return nil, context.Canceled
	}), func() { closed.Add(1) })
	d.Close()
	if d.Run() == nil {
		t.Fatal("closed deployment ran")
	}
	d.Close()
	if reads.Load() != 0 || closed.Load() != 1 {
		t.Fatal("closed deployment read or released ownership incorrectly")
	}
}
