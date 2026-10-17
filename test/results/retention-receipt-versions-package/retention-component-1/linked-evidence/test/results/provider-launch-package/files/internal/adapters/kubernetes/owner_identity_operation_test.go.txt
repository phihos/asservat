package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// These tests cover only the opaque operation's ordering/lifetime boundary.
// The synthetic root does not qualify actual native, SQL, or installer proof.
func ownerIdentityOperationTestHandle(t *testing.T) (*OwnerIdentityOperation, *OwnerIdentityRoleRoot, context.Context, *atomic.Int64) {
	t.Helper()
	input, state, now := ownerIdentityPrivateStateFixture(t)
	resources, _, _, _ := ownerIdentityActivationFixture(t)
	clock := new(atomic.Int64)
	clock.Store(now.UnixNano())
	resources.preparer.protection.observer.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	original := now.Add(5 * time.Second)
	rootCtx, rootCancel := context.WithCancel(context.Background())
	t.Cleanup(rootCancel)
	root := &OwnerIdentityRoleRoot{resources: resources, input: input, ctx: rootCtx, cancel: rootCancel, busy: true}
	call, cancel := context.WithDeadline(rootCtx, original)
	snapshot := contracts.OwnerIdentityRoleSnapshot{State: state, UID: ownerID(9301), ResourceVersion: "7", ValidUntil: original}
	op := &OwnerIdentityOperation{root: root, cancel: cancel, phase: ownerIdentityOperationInitial, initial: ownerIdentityOperationNative{roles: snapshot, until: original}, expected: snapshot, original: original, until: original}
	call = context.WithValue(call, ownerIdentityOperationContextKey{}, op)
	op.ctx, root.ownerOperation = call, op
	t.Cleanup(op.closeAndJoin)
	return op, root, call, clock
}

func TestOwnerIdentityOperationRetainsShorterAdmittedPhaseDeadline(t *testing.T) {
	op, root, original, clock := ownerIdentityOperationTestHandle(t)
	shortEnd := op.original.Add(-2 * time.Second)
	short, cancel := context.WithDeadline(original, shortEnd)
	defer cancel()
	admitted, err := op.AdmittedOwnerIdentityRoles(short, root)
	if err != nil || !admitted.ValidUntil.Equal(shortEnd) {
		t.Fatalf("short admission bound: %v %s", err, admitted.ValidUntil)
	}
	// The later caller supplies the original longer context. It cannot undo
	// the shorter successful phase, even before that shorter interval expires.
	if err = op.begin(original, root, ownerIdentityOperationRoleLock, ownerIdentityOperationReadingCurrent); err != nil {
		t.Fatal(err)
	}
	if !op.until.Equal(shortEnd) {
		t.Fatal("later original context extended admitted interval")
	}
	if err = op.finish(original, root, ownerIdentityOperationReadingCurrent, ownerIdentityOperationCurrent, nil); err != nil {
		op.work.Done()
		t.Fatal(err)
	}
	op.work.Done()
	current, err := op.roleCopy(op.expected)
	if err != nil || !current.ValidUntil.Equal(shortEnd) {
		t.Fatal("result lost earlier phase bound")
	}
	clock.Store(shortEnd.Add(time.Nanosecond).UnixNano())
	if err = op.begin(original, root, ownerIdentityOperationCurrent, ownerIdentityOperationReadingFinal); err == nil {
		op.work.Done()
		t.Fatal("later phase admitted after retained shorter end")
	}
	if op.ctx.Err() == nil {
		t.Fatal("expired phase did not poison original operation")
	}
}

func TestOwnerIdentityOperationRejectsDetachedAndRepeatedCalls(t *testing.T) {
	for _, name := range []string{"zero", "other-root", "detached-context", "canceled-phase", "closed-root", "repeated-phase"} {
		t.Run(name, func(t *testing.T) {
			op, root, ctx, _ := ownerIdentityOperationTestHandle(t)
			switch name {
			case "zero":
				op = &OwnerIdentityOperation{}
			case "other-root":
				root = &OwnerIdentityRoleRoot{}
			case "detached-context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), op.original)
				defer cancel()
			case "canceled-phase":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed-root":
				root.mu.Lock()
				root.closed = true
				root.mu.Unlock()
			case "repeated-phase":
				if _, err := op.AdmittedOwnerIdentityRoles(ctx, root); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := op.AdmittedOwnerIdentityRoles(ctx, root); err == nil {
				t.Fatal("invalid operation admitted")
			}
		})
	}
}

func TestOwnerIdentityOperationCloseJoinsAdmittedRead(t *testing.T) {
	op, root, ctx, _ := ownerIdentityOperationTestHandle(t)
	if err := op.begin(ctx, root, ownerIdentityOperationInitial, ownerIdentityOperationReadingCurrent); err != nil {
		t.Fatal(err)
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(op.work.Done) }
	defer release()
	closed := make(chan struct{})
	go func() { op.closeAndJoin(); close(closed) }()
	<-op.ctx.Done()
	select {
	case <-closed:
		t.Fatal("close returned before admitted work joined")
	default:
	}
	if err := op.finish(ctx, root, ownerIdentityOperationReadingCurrent, ownerIdentityOperationCurrent, nil); err == nil {
		t.Fatal("canceled work published next phase")
	}
	release()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("local join did not finish")
	}
	if err := op.begin(ctx, root, ownerIdentityOperationCurrent, ownerIdentityOperationReadingFinal); err == nil {
		op.work.Done()
		t.Fatal("closed operation accepted new work")
	}
}

type ownerIdentityOperationDeadlineBarrier struct {
	context.Context
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *ownerIdentityOperationDeadlineBarrier) Deadline() (time.Time, bool) {
	deadline, ok := s.Context.Deadline()
	s.once.Do(func() { close(s.entered); <-s.release })
	return deadline, ok
}

func TestOwnerIdentityOperationCancellationWhileWaitingForPhaseMutex(t *testing.T) {
	for _, phase := range []string{"begin", "finish"} {
		t.Run(phase, func(t *testing.T) {
			op, root, original, _ := ownerIdentityOperationTestHandle(t)
			if phase == "finish" {
				if err := op.begin(original, root, ownerIdentityOperationInitial, ownerIdentityOperationRoleLock); err != nil {
					t.Fatal(err)
				}
				defer op.work.Done()
			}
			call, cancel := context.WithCancel(original)
			defer cancel()
			barrier := &ownerIdentityOperationDeadlineBarrier{Context: call, entered: make(chan struct{}), release: make(chan struct{})}
			op.mu.Lock()
			result := make(chan error, 1)
			go func() {
				if phase == "begin" {
					result <- op.begin(barrier, root, ownerIdentityOperationInitial, ownerIdentityOperationRoleLock)
				} else {
					result <- op.finish(barrier, root, ownerIdentityOperationRoleLock, ownerIdentityOperationCurrent, nil)
				}
			}()
			<-barrier.entered // owned() has already checked both context errors.
			cancel()
			close(barrier.release)
			op.mu.Unlock()
			if err := <-result; err == nil {
				if phase == "begin" {
					op.work.Done()
				}
				t.Fatal("phase published after cancellation during mutex wait")
			}
			if op.ctx.Err() == nil {
				t.Fatal("failed phase did not cancel its original owner")
			}
		})
	}
}

func TestOwnerIdentityOperationRoleAttemptIsSingleUse(t *testing.T) {
	op, root, ctx, _ := ownerIdentityOperationTestHandle(t)
	// Explicit synthetic setup for this local phase-state regression only.
	op.phase = ownerIdentityOperationCurrent
	op.purpose, op.fresh = contracts.OwnerIdentityRolePurposes()[0], true
	purpose, fresh, err := op.OwnerIdentityRoleAttempt(ctx, root)
	if err != nil || purpose != op.purpose || !fresh {
		t.Fatal("original role attempt unavailable", err)
	}
	if _, _, err := op.OwnerIdentityRoleAttempt(ctx, root); err == nil {
		t.Fatal("same admitted role effect could be consumed twice")
	}
	if op.ctx.Err() == nil {
		t.Fatal("repeated role attempt did not poison original operation")
	}
}

func TestOwnerIdentityOperationFinalCannotSkipActualCurrentPhase(t *testing.T) {
	op, root, ctx, _ := ownerIdentityOperationTestHandle(t)
	if _, err := op.AdmittedOwnerIdentityRoles(ctx, root); err != nil {
		t.Fatal(err)
	}
	// The fixture has no native source clients: the order check must reject
	// before attempting any network read, even with valid original context.
	if _, err := op.ReadOwnerIdentityRolesFinal(ctx, root); err == nil {
		t.Fatal("final proof skipped actual post-lock current phase")
	}
	if op.ctx.Err() == nil {
		t.Fatal("out-of-order phase did not cancel original operation")
	}
}
