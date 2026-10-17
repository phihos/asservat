package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationWorkerInputTransitionsPreserveSiblingsAndOriginalPermit(t *testing.T) {
	_, complete, _ := configurationWorkerInputStateFixture(t)
	pending := complete
	p := *complete.WorkerInputs
	p.Receipt = nil
	pending.WorkerInputs = &p
	original := pending
	original.WorkerInputs = nil
	if !configurationWorkerInputTransition(original, pending) || !configurationWorkerInputTransition(pending, complete) {
		t.Fatal("fixed claim/receipt transition rejected")
	}
	if configurationWorkerInputTransition(original, complete) || configurationWorkerInputTransition(complete, complete) || configurationWorkerInputTransition(pending, pending) {
		t.Fatal("unacknowledged or repeat transition accepted")
	}
	for name, change := range map[string]func(*contracts.InitialRuntimeResourceState){
		"permit": func(v *contracts.InitialRuntimeResourceState) {
			q := *v.WorkerInputs
			q.Until = q.Until.Add(time.Second)
			v.WorkerInputs = &q
		},
		"predecessor": func(v *contracts.InitialRuntimeResourceState) {
			q := *v.WorkerInputs
			q.SQLProjection.UID = ownerID(14970)
			v.WorkerInputs = &q
		},
		"capacity sibling":  func(v *contracts.InitialRuntimeResourceState) { v.CapacityProjection = nil },
		"cleanup sibling":   func(v *contracts.InitialRuntimeResourceState) { v.CleanupProjection = nil },
		"original resource": func(v *contracts.InitialRuntimeResourceState) { v.SetupID = ownerID(14971) },
	} {
		t.Run(name, func(t *testing.T) {
			next := complete
			change(&next)
			if configurationWorkerInputTransition(pending, next) {
				t.Fatal("cross-purpose or original fact mutation accepted")
			}
		})
	}
}

func TestConfigurationWorkerInputsExternalCloseCancelsThenJoinsActiveCall(t *testing.T) {
	life, cancel := context.WithCancel(context.Background())
	s := &ConfigurationWorkerInputs{ctx: life, cancel: cancel}
	call, release, err := s.enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-call.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel active call")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before actual call joined")
	default:
	}
	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to join completed call")
	}
	if _, _, err := s.enter(context.Background()); err == nil {
		t.Fatal("closed producer admitted another call")
	}
}
