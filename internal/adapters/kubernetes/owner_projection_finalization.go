package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// A separate read-only purpose. Implementations cannot obtain an effect method
// or an execution handle from this type. Entry exposes no credential journal.
type OwnerProjectionFinalizationVerification interface {
	FinalizeOwnerProjectionOperation(context.Context, *OwnerProjectionFinalization) (OwnerProjectionAdvance, error)
}

type ownerProjectionFinalizationKey struct{}

type OwnerProjectionFinalization struct {
	self           *OwnerProjectionFinalization
	controller     *ProviderOwnerProjection
	pending        *ownerProjectionPending
	prefix         *ownerProjectionPreflight
	provider       ownerIdentityProviderObservation
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	work           sync.WaitGroup
	closed         bool
	until          time.Time
	phase          atomic.Uint32
	versionMatched atomic.Bool
	first, current ownerIdentityOperationNative
	input          contracts.OwnerDeployment
	activation     contracts.OwnerIdentityActivation
	data           map[string][]byte
	// failure keeps the first callback failure's closed codes; the SQL facet
	// returns only its own normalized error.
	failure ownerProjectionDiagnosticSlot
}

// recordFailure retains a callback failure's closed codes and returns it.
func (s *OwnerProjectionFinalization) recordFailure(check ownerProjectionCheck, err error) {
	if err != nil && s != nil && s.self == s {
		s.failure.first.CompareAndSwap(nil, projectionFixedCodes(projectionDiagnostic(check, err)))
	}
}

// Finalize can be attempted once for the original execution. A failed or lost
// finalizer cannot be retried by Inspect, a copied controller or a new controller
// over this live root. Every result remains non-authoritative until it returns.
func (s *ProviderOwnerProjection) Finalize(ctx context.Context) (OwnerProjectionAdvance, error) {
	var zero OwnerProjectionAdvance
	if s == nil || s.self != s || s.projection == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	verification, ok := s.verification.(OwnerProjectionFinalizationVerification)
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	root := s.projection.root
	root.mu.Lock()
	owned := !root.closed && root.ctx.Err() == nil && root.splitProjection == s
	root.mu.Unlock()
	if !owned {
		return zero, cfg.ErrUnavailable
	}
	s.mu.Lock()
	p := s.pending
	if s.inFlight || !s.split || p == nil || p.controller != s || p.consumed {
		s.mu.Unlock()
		return zero, cfg.ErrUnavailable
	}
	p.consumed = true
	s.inFlight = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.inFlight = false; s.mu.Unlock() }()
	if !p.ready() || p.semanticVersion <= 0 {
		return zero, cfg.ErrUnavailable
	}
	started := time.Now()
	// The pending step's original window left at start, for the stop message.
	window := p.originalEnd().Sub(started).Round(time.Millisecond)
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	call, bound := context.WithDeadline(call, p.originalEnd())
	defer bound()
	parent := call // remains meaningful after intentional child cleanup cancellation
	call, cancel := context.WithCancel(call)
	joined := make(chan struct{})
	watch := context.AfterFunc(p.caller, func() { cancel(); close(joined) })
	finishCaller := sync.OnceFunc(func() {
		cancel()
		if !watch() {
			<-joined
		}
	})
	defer finishCaller()
	call, release, err := s.projection.borrowProviderCall(call)
	if err != nil {
		return zero, err
	}
	release = sync.OnceFunc(release)
	defer release()
	proof, err := s.projection.observeProvider(call)
	if err != nil {
		return zero, projectionDiagnostic(projectionCheckProviderObserve, err)
	}
	call, narrow := context.WithDeadline(call, proof.until)
	defer narrow()
	effects, ok := root.bridge.effects.(fleetapp.InitialRuntimeOwnerBridgeEffects)
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	var out OwnerProjectionAdvance
	var finalization *OwnerProjectionFinalization
	call = context.WithValue(call, ownerProjectionControllerKey{}, s)
	err = root.withOwnerLifetime(call, func(current context.Context) error {
		return root.bridge.withOperation(current, func(original context.Context) error {
			prefix, e := s.projection.readProjectionPreflight(original, proof)
			if e != nil {
				return e
			}
			bounded, end := context.WithDeadline(original, prefix.until)
			defer end()
			bounded = context.WithValue(bounded, ownerProjectionPreflightKey{}, prefix)
			prefix.ctx = bounded
			return effects.WithInitialRuntimeOwnerBridge(bounded, prefix.source.fleet, func(locked context.Context) error {
				f := &OwnerProjectionFinalization{controller: s, pending: p, prefix: prefix, provider: proof, until: prefix.until}
				f.self = f
				finalization = f
				lifetime, cancel := context.WithCancel(context.WithValue(locked, ownerProjectionFinalizationKey{}, f))
				f.ctx, f.cancel = lifetime, cancel
				defer func() {
					f.closeAndJoin()
					clearRuntimeProjection(f.data)
					f.first = ownerIdentityOperationNative{}
					f.current = ownerIdentityOperationNative{}
					f.data = nil
					f.phase.Store(5)
				}()
				var err error
				out, err = verification.FinalizeOwnerProjectionOperation(lifetime, f)
				if err != nil {
					return err
				}
				if f.phase.Load() != 4 || out.Status != ownerProjectionStepResult(p.step) || out.Snapshot.UID != f.current.retained.resources.UID || out.Snapshot.ResourceVersion != f.current.retained.resources.ResourceVersion || !equalJSON(out.Snapshot.State, f.current.retained.resources.State) || initialHandoverDeadline(lifetime, root.resources.now, f.until) != nil {
					return cfg.ErrUnavailable
				}
				return nil
			})
		})
	})
	if err != nil {
		detail := projectionDiagnostic(projectionCheckFinalNative, err)
		detail.detail = projectionFailureClass(err) + " after " + time.Since(started).Round(time.Millisecond).String() + ", original window " + window.String() + " at start"
		// The SQL facet's closed step and the first callback failure.
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			detail.detail += "; " + fixed.FixedStep()
		}
		if finalization != nil && detail.inner == nil {
			detail.inner = finalization.failure.first.Load()
		}
		detail.cause = cfg.ErrUnavailable
		return zero, detail
	}
	if call.Err() != nil || p.caller.Err() != nil || !root.resources.now().Before(out.Snapshot.ValidUntil) {
		return zero, cfg.ErrUnavailable
	}
	// Joining owned cancellation callbacks is part of finalization. It may
	// block; do it before publishing success, then check the original live
	// parent rather than the child deliberately cancelled by release.
	release()
	finishCaller()
	root.mu.Lock()
	root.resources.mu.Lock()
	s.mu.Lock()
	if root.closed || root.ctx.Err() != nil || root.splitProjection != s || s.pending != p || !p.consumed || root.resources.closed || root.resources.ctx.Err() != nil || parent.Err() != nil || p.caller.Err() != nil || !root.resources.now().Before(out.Snapshot.ValidUntil) {
		s.mu.Unlock()
		root.resources.mu.Unlock()
		root.mu.Unlock()
		return zero, cfg.ErrUnavailable
	}
	s.knownChildren = p.children
	p.resources.ResourceVersion = out.Snapshot.ResourceVersion
	p.resources.ValidUntil = out.Snapshot.ValidUntil
	s.lastVerified = p
	s.pending = nil
	s.mu.Unlock()
	root.resources.mu.Unlock()
	root.mu.Unlock()
	return out, nil
}

func (s *OwnerProjectionFinalization) enter(ctx context.Context, root *OwnerIdentityRoleRoot, old, next uint32) error {
	if s == nil || s.self != s || s.controller == nil || s.controller.projection == nil || s.controller.projection.root != root || s.pending == nil || s.pending.controller != s.controller || ctx == nil || s.ctx == nil || ctx.Value(ownerProjectionFinalizationKey{}) != s || ctx.Err() != nil || s.ctx.Err() != nil || s.pending.caller.Err() != nil {
		return cfg.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return cfg.ErrUnavailable
	}
	root.mu.Lock()
	owned := !root.closed && root.busy && root.ctx.Err() == nil && root.splitProjection == s.controller && root.ownerOperation == nil
	root.mu.Unlock()
	deadline, bounded := ctx.Deadline()
	if !owned || !bounded || !s.phase.CompareAndSwap(old, next) {
		return cfg.ErrUnavailable
	}
	if deadline.After(s.until) || initialHandoverDeadline(ctx, root.resources.now, s.until) != nil {
		s.phase.Store(5)
		return cfg.ErrUnavailable
	}
	s.until = identity.Earlier(s.until, deadline)
	s.work.Add(1)
	return nil
}

// The SQL facet calls this before pool acquisition. It cannot return a password,
// a completed native proof or an effect-capable handle from an incomplete prefix.
func (s *OwnerProjectionFinalization) AdmitOwnerProjectionFinalization(ctx context.Context, root *OwnerIdentityRoleRoot) (_ contracts.OwnerIdentityRoles, _ time.Time, failure error) {
	defer func() { s.recordFailure(projectionCheckFinalBegin, failure) }()
	if err := s.enter(ctx, root, 0, 10); err != nil {
		return contracts.OwnerIdentityRoles{}, time.Time{}, err
	}
	defer s.work.Done()
	input, until := root.input, s.until
	s.phase.Store(1)
	return input, until, nil
}

// Capture/compare the version while the SQL authority row is already SHARE
// locked. Suspension/resumption and semantic ABA cannot be refreshed away.
func (s *OwnerProjectionOperation) BindOwnerProjectionSemanticVersion(ctx context.Context, root *OwnerIdentityRoleRoot, version int64) error {
	if !s.OwnerProjectionExecutionOnly() || version <= 0 || !s.owner.owned(ctx, root) {
		return cfg.ErrUnavailable
	}
	s.owner.mu.Lock()
	valid := s.owner.phase == ownerIdentityOperationRoleLock && !s.owner.active && s.pending.semanticVersion == 0
	if valid {
		s.pending.semanticVersion = version
	}
	s.owner.mu.Unlock()
	if !valid {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *OwnerProjectionFinalization) MatchOwnerProjectionSemanticVersion(ctx context.Context, root *OwnerIdentityRoleRoot, version int64) (failure error) {
	defer func() { s.recordFailure(projectionCheckFinalBegin, failure) }()
	if s == nil || s.self != s || s.phase.Load() != 1 || s.pending == nil || s.pending.semanticVersion <= 0 || version != s.pending.semanticVersion || s.controller == nil || s.controller.projection.root != root || ctx == nil || ctx.Value(ownerProjectionFinalizationKey{}) != s || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if !s.versionMatched.CompareAndSwap(false, true) {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *OwnerProjectionFinalization) ReadOwnerProjectionFinalizationAfterLock(ctx context.Context, root *OwnerIdentityRoleRoot) (_ contracts.OwnerIdentityRoleSnapshot, failure error) {
	check := projectionCheckFinalBegin
	defer func() { s.recordFailure(check, failure) }()
	var zero contracts.OwnerIdentityRoleSnapshot
	if err := s.enter(ctx, root, 1, 12); err != nil {
		return zero, err
	}
	defer s.work.Done()
	if !s.versionMatched.Load() {
		return zero, cfg.ErrUnavailable
	}
	check = projectionCheckFinalNative
	actual, err := s.prefix.complete(ctx, s.provider)
	if err != nil {
		return zero, err
	}
	ctx, narrow := context.WithDeadline(ctx, actual.until)
	defer narrow()
	check = projectionCheckFinalOriginals
	p := s.pending
	expected := p.original
	if actual.retained.resources.UID != p.resources.UID || !equalJSON(actual.retained.resources.State, p.resources.State) {
		return zero, cfg.ErrChanged
	}
	if p.journalUnknown {
		if actual.retained.resources.ResourceVersion == p.journalBefore {
			return zero, cfg.ErrChanged
		}
	} else if actual.retained.resources.ResourceVersion != p.resources.ResourceVersion {
		return zero, cfg.ErrChanged
	}
	expected.retained.resources = actual.retained.resources
	sanitized := ownerProjectionPublicPins(actual)
	if difference := ownerIdentityOperationOriginalDifference(expected, actual); difference != ownerOperationNoFailure {
		return zero, ownerOperationError(difference, cfg.ErrChanged)
	}
	check = projectionCheckFinalRoles
	if sanitized.roles.UID != p.roles.UID || sanitized.roles.ResourceVersion != p.roles.ResourceVersion || !equalJSON(sanitized.roles.State, p.roles.State) {
		return zero, cfg.ErrChanged
	}
	check = projectionCheckFinalInput
	projection := s.controller.projection
	if err = projection.originalOperationInput(ctx, actual); err != nil {
		return zero, err
	}
	if err = projection.operationProviderMaterial(ctx, actual, s.provider); err != nil {
		return zero, err
	}
	a := contracts.OwnerIdentityActivation{Input: root.input, RoleRoot: contracts.WorkerObjectReference{Name: root.name(), UID: actual.roles.UID}, RoleSetupID: actual.roles.State.OperationID, ResourcesCreatedAt: actual.retained.resources.State.CreatedAt, ResourcesUntil: actual.retained.resources.State.Until}
	in, _, data, digest, err := ownerIdentityProjectionMaterial(projection.input, a, actual.roles, OwnerIdentityProviderMaterial{}, root.resources.now())
	if err != nil {
		return zero, err
	}
	s.data = data
	s.input, s.activation = in, a
	if actual.retained.resources.State.OwnerIdentity == nil || digest != actual.retained.resources.State.OwnerIdentity.PublicDigest {
		return zero, cfg.ErrChanged
	}
	s.first, s.current = actual, actual
	s.until = identity.Earlier(s.until, actual.until)
	check = projectionCheckFinalChildren
	if err = s.readChildren(ctx); err != nil {
		return zero, err
	}
	check = projectionCheckFinalLaunch
	if err = s.checkLaunch(actual); err != nil {
		return zero, err
	}
	check = projectionCheckFinalFinish
	out, err := s.copyRoles(ctx, root)
	if err == nil {
		s.phase.Store(2)
	}
	return out, err
}

// One actual final current graph, under the fresh finalizer's original negative
// proof. It has no journal CAS, object CREATE, launch or credential DDL method.
func (s *OwnerProjectionFinalization) ReadOwnerProjectionFinalizationCurrent(ctx context.Context, root *OwnerIdentityRoleRoot) (_ contracts.OwnerIdentityRoleSnapshot, failure error) {
	check := projectionCheckFinalBegin
	defer func() { s.recordFailure(check, failure) }()
	var zero contracts.OwnerIdentityRoleSnapshot
	if err := s.enter(ctx, root, 2, 13); err != nil {
		return zero, err
	}
	defer s.work.Done()
	check = projectionCheckCurrentNative
	actual, err := root.readOwnerIdentityOperationCurrent(ctx, s.first, s.first.retained.resources, s.first.roles)
	if err != nil {
		return zero, err
	}
	check = projectionCheckFinalOriginals
	if difference := ownerIdentityOperationOriginalDifference(s.first, actual); difference != ownerOperationNoFailure {
		return zero, ownerOperationError(difference, cfg.ErrUnavailable)
	}
	check = projectionCheckCurrentInput
	ctx, narrow := context.WithDeadline(ctx, actual.until)
	defer narrow()
	projection := s.controller.projection
	if err = projection.originalOperationInput(ctx, actual); err != nil {
		return zero, err
	}
	if err = projection.operationProviderMaterial(ctx, actual, s.provider); err != nil {
		return zero, err
	}
	s.current = actual
	s.until = identity.Earlier(s.until, actual.until)
	check = projectionCheckFinalChildren
	if err = s.readChildren(ctx); err != nil {
		return zero, err
	}
	check = projectionCheckFinalLaunch
	if err = s.checkLaunch(actual); err != nil {
		return zero, err
	}
	check = projectionCheckFinalFinish
	out, err := s.copyRoles(ctx, root)
	if err == nil {
		s.phase.Store(3)
	}
	return out, err
}
func (s *OwnerProjectionFinalization) checkLaunch(actual ownerIdentityOperationNative) error {
	switch s.pending.step {
	case ownerProjectionLaunch, ownerProjectionAcknowledgeLaunch, ownerProjectionReadLaunch:
		if !ownerIdentityClaimedLaunchObject(actual.source.ownerDeployment, actual.retained.resources.State, s.controller.projection.root.input) {
			return cfg.ErrChanged
		}
	}
	return nil
}
func (s *OwnerProjectionFinalization) readChildren(ctx context.Context) error {
	for i := 0; i < ownerProjectionRequiredChildren(s.pending.step); i++ {
		purpose := "credentials"
		if i == 1 {
			purpose = "configuration"
		}
		got, err := s.controller.projection.readObject(ctx, s.current.retained.resources.State.OwnerIdentity, purpose, s.input, s.activation, s.data)
		want := s.pending.children[i]
		if err != nil || want == nil || got.Object != want.Object || got.ResourceVersion != want.ResourceVersion {
			return cfg.ErrUnavailable
		}
	}
	return nil
}
func (s *OwnerProjectionFinalization) copyRoles(ctx context.Context, root *OwnerIdentityRoleRoot) (contracts.OwnerIdentityRoleSnapshot, error) {
	var zero contracts.OwnerIdentityRoleSnapshot
	raw, err := json.Marshal(s.current.roles.State)
	defer clear(raw)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	state, err := contracts.DecodeOwnerIdentityRoleState(bytes.NewReader(raw))
	if err != nil || initialHandoverDeadline(ctx, root.resources.now, s.until) != nil {
		return zero, cfg.ErrUnavailable
	}
	out := s.current.roles
	out.State = state
	out.ValidUntil = s.until
	return out, nil
}
func (s *OwnerProjectionFinalization) OwnerProjectionFinalizationResult(ctx context.Context, root *OwnerIdentityRoleRoot) (OwnerProjectionAdvance, error) {
	var zero OwnerProjectionAdvance
	if err := s.enter(ctx, root, 3, 14); err != nil {
		return zero, err
	}
	defer s.work.Done()
	out := s.current.retained.resources
	raw, err := json.Marshal(out.State)
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	state, err := contracts.DecodeInitialRuntimeResourceState(bytes.NewReader(raw))
	if err != nil || initialHandoverDeadline(ctx, root.resources.now, s.until) != nil {
		return zero, cfg.ErrUnavailable
	}
	out.State = state
	out.ValidUntil = s.until
	s.phase.Store(4)
	return OwnerProjectionAdvance{Status: ownerProjectionStepResult(s.pending.step), Snapshot: out}, nil
}

// Retained opaque handles cannot let an asynchronous read outlive the owning
// SQL callback, root/resource borrow, or clearing of reconstructed credentials.
func (s *OwnerProjectionFinalization) closeAndJoin() {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.work.Wait()
}
