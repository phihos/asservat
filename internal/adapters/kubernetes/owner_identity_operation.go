package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

type ownerIdentityOperationPhase uint8

const (
	ownerIdentityOperationInitial ownerIdentityOperationPhase = iota + 1
	ownerIdentityOperationRoleLock
	ownerIdentityOperationReadingCurrent
	ownerIdentityOperationCurrent
	ownerIdentityOperationReadingRoleAttempt
	ownerIdentityOperationRoleEffect
	ownerIdentityOperationReadingRoleReceipt
	ownerIdentityOperationRoleAcknowledged
	ownerIdentityOperationReadingProjection
	ownerIdentityOperationProjectionApplied
	ownerIdentityOperationReadingFinal
	ownerIdentityOperationFinal
	ownerIdentityOperationReadingProjectionResult
	ownerIdentityOperationProjectionComplete
	ownerIdentityOperationClosed
)

type ownerIdentityOperationContextKey struct{}

// OwnerIdentityOperation is a concrete admitted installer operation, not a
// serializable proof or general source interface. Only the original native
// root mints it inside its joined operation. The fresh SQL producer pins that
// exact root; a zero value or a copied caller snapshot cannot be admitted.
type OwnerIdentityOperation struct {
	mu               sync.Mutex
	work             sync.WaitGroup
	root             *OwnerIdentityRoleRoot
	ctx              context.Context
	cancel           context.CancelFunc
	phase            ownerIdentityOperationPhase
	active           bool
	initial          ownerIdentityOperationNative
	current          ownerIdentityOperationNative
	expected         contracts.OwnerIdentityRoleSnapshot
	purpose          string
	fresh            bool
	inspection       bool
	createDispatched bool
	original         time.Time
	until            time.Time
	// failure keeps the first native callback failure's closed codes; the SQL
	// facet returns only its own normalized step.
	failure atomic.Pointer[ownerOperationDiagnostic]
}

func (s *OwnerIdentityOperation) recordFailure(check ownerOperationCheck, err error) {
	if s != nil && err != nil {
		var d *ownerOperationDiagnostic
		if !errors.As(err, &d) || d == nil {
			d = &ownerOperationDiagnostic{check: check}
		}
		s.failure.CompareAndSwap(nil, projectionNativeCodes(d))
	}
}

// Implemented by the purpose-fixed fresh PostgreSQL producer. The concrete
// native handle prevents a DTO/callback from replacing its post-lock reads.
// This is separate from the unchanged legacy OwnerIdentityRoleVerification.
type OwnerIdentityOperationVerification interface {
	VerifyOwnerIdentityOperation(context.Context, *OwnerIdentityOperation) (contracts.OwnerIdentityRoleSnapshot, error)
}

// VerifyProviderOwnerIdentityRoles performs the complete fresh-only readonly
// role verification. Creation/projection/launch are distinct admitted methods;
// this method cannot turn a historical receipt into any of those effects.
func (s *OwnerIdentityRoleRoot) VerifyProviderOwnerIdentityRoles(ctx context.Context, verification OwnerIdentityOperationVerification) (contracts.OwnerIdentityRoleSnapshot, error) {
	var out contracts.OwnerIdentityRoleSnapshot
	if s == nil || verification == nil || ctx == nil || ctx.Err() != nil || s.input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return out, cfg.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	err := s.providerOperation(call, true, func(bounded context.Context) (ownerIdentityOperationNative, error) {
		first, err := s.readOwnerIdentityOperationNative(bounded, s.input.LayoutDigest, true)
		if err != nil || first.missing {
			return ownerIdentityOperationNative{}, cfg.ErrUnavailable
		}
		return first, nil
	}, func(bounded context.Context, first ownerIdentityOperationNative) error {
		var err error
		live, cancel := context.WithDeadline(bounded, first.until)
		defer cancel()
		op := &OwnerIdentityOperation{root: s, cancel: cancel, phase: ownerIdentityOperationInitial, initial: first, current: first, expected: first.roles, original: first.until, until: first.until}
		live = context.WithValue(live, ownerIdentityOperationContextKey{}, op)
		op.ctx = live
		s.mu.Lock()
		if s.closed || !s.busy || s.ownerOperation != nil || s.ctx.Err() != nil {
			s.mu.Unlock()
			return cfg.ErrUnavailable
		}
		s.ownerOperation = op
		s.mu.Unlock()
		defer func() {
			op.closeAndJoin()
			s.mu.Lock()
			if s.ownerOperation == op {
				s.ownerOperation = nil
			}
			s.mu.Unlock()
		}()
		out, err = verification.VerifyOwnerIdentityOperation(live, op)
		if err != nil {
			return err
		}
		op.mu.Lock()
		complete := op.phase == ownerIdentityOperationFinal && live.Err() == nil && s.resources.now().Before(op.until) && !out.ValidUntil.After(op.until)
		op.mu.Unlock()
		if !complete || out.UID != first.roles.UID || out.ResourceVersion != first.roles.ResourceVersion || !equalJSON(out.State, first.roles.State) || out.ValidUntil.After(first.until) || !s.resources.now().Before(out.ValidUntil) {
			return cfg.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, err
	}
	return out, nil
}

// AdmittedOwnerIdentityRoles exposes only the original actual pre-role-lock
// observation. It is deliberately not named Read/current and cannot be called
// twice. The private context marker proves call ownership, never read caching.
func (s *OwnerIdentityOperation) AdmittedOwnerIdentityRoles(ctx context.Context, root *OwnerIdentityRoleRoot) (contracts.OwnerIdentityRoleSnapshot, error) {
	if err := s.begin(ctx, root, ownerIdentityOperationInitial, ownerIdentityOperationRoleLock); err != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, err
	}
	defer s.work.Done()
	out, err := s.roleCopy(s.expected)
	if err != nil || s.finish(ctx, root, ownerIdentityOperationRoleLock, ownerIdentityOperationRoleLock, nil) != nil {
		s.poison()
		return contracts.OwnerIdentityRoleSnapshot{}, cfg.ErrUnavailable
	}
	return out, nil
}

// ReadOwnerIdentityRolesAfterLock performs actual C4/S17 current reads after
// the concrete SQL producer acquires its recovery/advisory locks. It preserves
// the initial native interval and cannot renew an enforcement observation.
func (s *OwnerIdentityOperation) ReadOwnerIdentityRolesAfterLock(ctx context.Context, root *OwnerIdentityRoleRoot) (contracts.OwnerIdentityRoleSnapshot, error) {
	var zero contracts.OwnerIdentityRoleSnapshot
	if err := s.begin(ctx, root, ownerIdentityOperationRoleLock, ownerIdentityOperationReadingCurrent); err != nil {
		return zero, err
	}
	defer s.work.Done()
	s.mu.Lock()
	until := s.until
	s.mu.Unlock()
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	actual, err := root.readOwnerIdentityOperationCurrent(call, s.initial, s.initial.retained.resources, s.expected)
	if err != nil {
		s.recordFailure(ownerCurrentEntry, err)
		s.poison()
		return zero, err
	}
	out, err := s.roleCopy(actual.roles)
	if err != nil || s.finish(call, root, ownerIdentityOperationReadingCurrent, ownerIdentityOperationCurrent, &actual) != nil {
		s.poison()
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

// ReadOwnerIdentityRolesFinal runs new independent native denial probes and
// original source/journal reads. SQL must still check current incarnation and
// finish its transaction before returning a verified result to the owner.
func (s *OwnerIdentityOperation) ReadOwnerIdentityRolesFinal(ctx context.Context, root *OwnerIdentityRoleRoot) (contracts.OwnerIdentityRoleSnapshot, error) {
	var zero contracts.OwnerIdentityRoleSnapshot
	expectedPhase := ownerIdentityOperationCurrent
	if s != nil && s.purpose != "" {
		expectedPhase = ownerIdentityOperationRoleEffect
		if !s.fresh && !s.inspection {
			expectedPhase = ownerIdentityOperationRoleAcknowledged
		}
	}
	if err := s.begin(ctx, root, expectedPhase, ownerIdentityOperationReadingFinal); err != nil {
		return zero, err
	}
	defer s.work.Done()
	s.mu.Lock()
	until := s.until
	s.mu.Unlock()
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	actual, err := root.readOwnerIdentityOperationNative(call, root.input.LayoutDigest, true)
	if err == nil {
		if difference := ownerIdentityOperationOriginalDifference(s.initial, actual); difference != ownerOperationNoFailure {
			err = ownerOperationError(difference, cfg.ErrUnavailable)
		} else if actual.roles.UID != s.expected.UID || actual.roles.ResourceVersion != s.expected.ResourceVersion || !equalJSON(actual.roles.State, s.expected.State) {
			err = ownerOperationError(ownerCurrentRoles, cfg.ErrUnavailable)
		}
	}
	if err != nil {
		s.recordFailure(ownerRootFinalNative, err)
		s.poison()
		return zero, cfg.ErrUnavailable
	}
	actual.roles.ValidUntil = identity.Earlier(actual.roles.ValidUntil, until)
	out, err := s.roleCopy(actual.roles)
	if err != nil || s.finish(call, root, ownerIdentityOperationReadingFinal, ownerIdentityOperationFinal, &actual) != nil {
		s.poison()
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

// Admission and closure share this mutex: no Add can race the final Wait.
// A second/concurrent/out-of-order call poisons the whole original operation;
// all native work already admitted by the first call must still join.
func (s *OwnerIdentityOperation) begin(ctx context.Context, root *OwnerIdentityRoleRoot, old, next ownerIdentityOperationPhase) error {
	if s == nil {
		return cfg.ErrUnavailable
	}
	owned := s.owned(ctx, root)
	s.mu.Lock()
	until := s.until
	if owned {
		deadline, _ := ctx.Deadline()
		until = identity.Earlier(until, deadline)
	}
	valid := owned && ctx.Err() == nil && s.ctx.Err() == nil && root.ctx.Err() == nil && s.phase == old && !s.active && root.resources != nil && root.resources.now().Before(until)
	if valid {
		s.until = until
		s.phase, s.active = next, true
		s.work.Add(1)
	}
	s.mu.Unlock()
	if !valid {
		s.poison()
		return cfg.ErrUnavailable
	}
	return nil
}

// The next phase and its narrowed data become visible atomically. There is no
// interval in which a subsequent method can consume the previous phase's data.
func (s *OwnerIdentityOperation) finish(ctx context.Context, root *OwnerIdentityRoleRoot, old, next ownerIdentityOperationPhase, actual *ownerIdentityOperationNative) error {
	owned := s.owned(ctx, root)
	s.mu.Lock()
	until := s.until
	if owned {
		deadline, _ := ctx.Deadline()
		until = identity.Earlier(until, deadline)
	}
	if actual != nil {
		until = identity.Earlier(until, actual.until)
	}
	valid := owned && ctx.Err() == nil && s.ctx.Err() == nil && root.ctx.Err() == nil && s.phase == old && s.active && root.resources != nil && root.resources.now().Before(until)
	if valid {
		s.until, s.phase, s.active = until, next, false
		if actual != nil {
			s.current = *actual
		}
	}
	s.mu.Unlock()
	if !valid {
		s.poison()
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *OwnerIdentityOperation) owned(ctx context.Context, root *OwnerIdentityRoleRoot) bool {
	if root == nil || s.root != root || ctx == nil || s.ctx == nil || ctx.Value(ownerIdentityOperationContextKey{}) != s || ctx.Err() != nil || s.ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(s.original) {
		return false
	}
	root.mu.Lock()
	owned := !root.closed && root.busy && root.ownerOperation == s && root.ctx != nil && root.ctx.Err() == nil
	root.mu.Unlock()
	return owned
}

func (s *OwnerIdentityOperation) poison() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.phase = ownerIdentityOperationClosed
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Only the outer admitted root invokes this join. Child methods poison without
// waiting for themselves; no closure creates new provider or native work.
func (s *OwnerIdentityOperation) closeAndJoin() {
	s.poison()
	s.work.Wait()
}

// Each result retains every previously admitted phase bound, even if the
// caller supplies the original longer context for a later phase.
func (s *OwnerIdentityOperation) roleCopy(in contracts.OwnerIdentityRoleSnapshot) (contracts.OwnerIdentityRoleSnapshot, error) {
	s.mu.Lock()
	in.ValidUntil = identity.Earlier(in.ValidUntil, s.until)
	s.mu.Unlock()
	return ownerIdentityOperationRoleCopy(in)
}

func ownerIdentityOperationRoleCopy(in contracts.OwnerIdentityRoleSnapshot) (contracts.OwnerIdentityRoleSnapshot, error) {
	raw, err := json.Marshal(in.State)
	defer clear(raw)
	if err != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, cfg.ErrUnavailable
	}
	state, err := contracts.DecodeOwnerIdentityRoleState(bytes.NewReader(raw))
	if err != nil {
		return contracts.OwnerIdentityRoleSnapshot{}, cfg.ErrUnavailable
	}
	in.State = state
	return in, nil
}
