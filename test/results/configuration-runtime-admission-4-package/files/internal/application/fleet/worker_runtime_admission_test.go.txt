package fleet

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func workerAdmissionQueued(t *testing.T, s *WorkerRuntimeAdmission, purpose workerRuntimePurpose) {
	t.Helper()
	for {
		s.mu.Lock()
		present, changed := s.slots[purpose] != nil, s.changed
		s.mu.Unlock()
		if present {
			return
		}
		select {
		case <-changed:
		case <-time.After(time.Second):
			t.Fatal("purpose did not enter the finite queue", purpose)
		}
	}
}

func TestWorkerRuntimeAdmissionPreservesFivePurposeFIFO(t *testing.T) {
	root, cancel := context.WithCancel(t.Context())
	s, err := NewWorkerRuntimeAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer cancel()
	first, err := s.WaitWrapRefresh(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	if duplicate, e := s.WaitWrapRefresh(t.Context()); e == nil || duplicate != nil {
		t.Fatal("duplicate active purpose admitted")
	}
	type admitted struct {
		purpose workerRuntimePurpose
		lease   *WorkerRuntimeAdmissionLease
		err     error
	}
	results := make(chan admitted, 4)
	for _, purpose := range []workerRuntimePurpose{workerUnwrapRefresh, workerOwnerAuditPurpose, workerCapacity, workerCleanup} {
		go func() {
			p, e := s.wait(root, purpose)
			results <- admitted{purpose, p, e}
			// Also join a lease which a fatal assertion did not receive/release.
			if p != nil {
				<-root.Done()
				p.Release()
			}
		}()
		workerAdmissionQueued(t, s, purpose)
		if duplicate, e := s.wait(t.Context(), purpose); e == nil || duplicate != nil {
			t.Fatal("duplicate pending purpose admitted")
		}
	}
	first.Release()
	for _, want := range []workerRuntimePurpose{workerUnwrapRefresh, workerOwnerAuditPurpose, workerCapacity, workerCleanup} {
		select {
		case got := <-results:
			if got.err != nil || got.purpose != want || got.lease == nil {
				t.Fatal("FIFO violated", got.purpose, want, got.err)
			}
			select {
			case <-results:
				t.Fatal("two effect purposes active")
			default:
			}
			got.lease.Release()
		case <-time.After(time.Second):
			t.Fatal("live purpose starved", want)
		}
	}
}

func TestWorkerRuntimeAdmissionExpiredObservationNeverGetsFreshWindow(t *testing.T) {
	s, err := NewWorkerRuntimeAdmission(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := s.WaitWrapRefresh(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	original, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	failed := make(chan error, 1)
	go func() {
		p, e := s.WaitOwnerAudit(original)
		if p != nil {
			p.Release()
		}
		failed <- e
	}()
	workerAdmissionQueued(t, s, workerOwnerAuditPurpose)
	<-original.Done()
	if e := <-failed; e == nil {
		t.Fatal("expired original observation gained admission")
	}
	first.Release()
	// A distinct later invocation is permitted, but supplies no authority and
	// retains its own existing child deadline exactly. The old one remains dead.
	call, end := context.WithTimeout(t.Context(), time.Second)
	defer end()
	p, err := s.WaitOwnerAudit(call)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release()
	want, _ := call.Deadline()
	got, ok := p.Context().Deadline()
	if !ok || !got.Equal(want) || original.Err() == nil {
		t.Fatal("queue reset an original interval")
	}
}

func TestWorkerRuntimeAdmissionCloseCancelsThenJoinsActiveOwner(t *testing.T) {
	root, cancel := context.WithCancel(t.Context())
	defer cancel()
	s, err := NewWorkerRuntimeAdmission(root)
	if err != nil {
		t.Fatal(err)
	}
	active, err := s.WaitCapacity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer active.Release()
	waiting := make(chan error, 1)
	go func() {
		p, e := s.WaitCleanup(t.Context())
		if p != nil {
			p.Release()
		}
		waiting <- e
	}()
	workerAdmissionQueued(t, s, workerCleanup)
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	<-active.Context().Done()
	if e := <-waiting; e == nil {
		t.Fatal("shutdown granted pending effect")
	}
	select {
	case <-closed:
		t.Fatal("cancelled owner was released before join")
	default:
	}
	if p, e := s.WaitWrapRefresh(t.Context()); e == nil || p != nil {
		t.Fatal("close admitted new work")
	}
	var copied WorkerRuntimeAdmissionLease
	reflect.ValueOf(&copied).Elem().Set(reflect.ValueOf(active).Elem())
	copied.Release()
	select {
	case <-closed:
		t.Fatal("copied lease released original owner")
	default:
	}
	active.Release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("joined owner did not release close")
	}
	// Repeated and concurrent Close must not wait for a stopped callback.
	s.Close()
}
