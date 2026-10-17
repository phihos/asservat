package bootstrap

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestCapacityWorkerClosesPoolsOnlyAfterActualOwnedCompletion(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	var closed atomic.Bool
	d := &CapacityWorkerDeployment{root: root, cancel: cancel, closers: []func(){func() { closed.Store(true) }}}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	runDone := make(chan error, 1)
	go func() {
		runDone <- d.run(context.Background(), func(call context.Context) error {
			close(entered)
			<-call.Done()
			close(canceled)
			<-release // A canceled but unjoined child still owns its resources.
			return call.Err()
		})
	}()
	<-entered
	closeDone := make(chan struct{})
	go func() { d.Close(); close(closeDone) }()
	<-canceled
	select {
	case <-closeDone:
		close(release)
		t.Fatal("close returned before the owned child joined")
	case <-time.After(20 * time.Millisecond):
	}
	if closed.Load() {
		close(release)
		t.Fatal("released scoped SQL pools before join")
	}
	if err := d.run(context.Background(), func(context.Context) error { t.Error("closed deployment admitted another owner"); return nil }); err == nil {
		close(release)
		t.Fatal("closed deployment reopened")
	}
	close(release)
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("child completion did not finish Run")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close failed to join")
	}
	if !closed.Load() {
		t.Fatal("scoped pools not closed after completion")
	}
}

func TestCapacityWorkerPreservesLeaseCancellationAndSingleOwner(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	d := &CapacityWorkerDeployment{root: root, cancel: cancel}
	lease, lose := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- d.run(lease, func(call context.Context) error { close(entered); <-call.Done(); return call.Err() })
	}()
	<-entered
	if err := d.run(context.Background(), func(context.Context) error { t.Error("second owner executed"); return nil }); err == nil {
		t.Fatal("multiple process owners")
	}
	lose()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Lease loss did not join capacity work")
	}
	if root.Err() == nil {
		t.Fatal("completed subsystem left its root live")
	}
}
