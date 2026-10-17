package kubernetes

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestWorkerProjectionCloseCancelsAndJoinsTheWholeBorrow(t *testing.T) {
	root, cancel := context.WithCancel(context.Background())
	s := &InitialRuntimeResources{ctx: root, cancel: cancel}
	caller, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	live, finish, err := s.borrowWorkerProjection(caller)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(finish) }
	defer release()
	// A completed helper read must not end the publisher's outer lifetime.
	_, readDone, err := s.borrowWorkerProjection(live)
	if err != nil {
		t.Fatal(err)
	}
	readDone()
	want, _ := caller.Deadline()
	got, _ := live.Deadline()
	if !want.Equal(got) {
		t.Fatal("borrow renewed the original caller deadline")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-live.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the later effect")
	}
	select {
	case <-closed:
		t.Fatal("Close claimed joined before effect release")
	default:
	}
	if _, _, err = s.borrowWorkerProjection(caller); err == nil {
		t.Fatal("closing resource admitted another effect")
	}
	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close failed to join actual completion")
	}
}

func TestWorkerProjectionBorrowRetainsParentCancellation(t *testing.T) {
	root, stop := context.WithCancel(context.Background())
	s := &InitialRuntimeResources{ctx: root, cancel: stop}
	defer s.Close()
	caller, cancel := context.WithCancel(context.Background())
	live, done, err := s.borrowWorkerProjection(caller)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	cancel()
	select {
	case <-live.Done():
	case <-time.After(time.Second):
		t.Fatal("parent cancellation detached")
	}
}
