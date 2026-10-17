package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// A process-local original-result pin, never an execution permit. In particular
// no password, provider token, credential payload or payload hash survives here.
// The original caller/root lifetime and every persisted claim date are unchanged.
type ownerProjectionControllerKey struct{}

type ownerProjectionPending struct {
	controller               *ProviderOwnerProjection
	caller                   context.Context
	original                 ownerIdentityOperationNative
	resources                contracts.InitialRuntimeResourceSnapshot
	roles                    contracts.OwnerIdentityRoleSnapshot
	children                 [2]*contracts.OwnerIdentityObjectReceipt
	step                     ownerProjectionStep
	journalBefore            string
	semanticVersion          int64
	journalUnknown, consumed bool
}

func ownerProjectionPublicPins(n ownerIdentityOperationNative) ownerIdentityOperationNative {
	n.object = nil
	n.retained.object = nil
	n.source.proof.native = nil
	n.roles.State.Roles = append([]contracts.PublicRuntimeRoleMaterial(nil), n.roles.State.Roles...)
	for i := range n.roles.State.Roles {
		n.roles.State.Roles[i].Password = ""
	}
	return n
}
func ownerProjectionChildIndex(purpose string) int {
	if purpose == "configuration" {
		return 1
	}
	return 0
}
func ownerProjectionRequiredChildren(step ownerProjectionStep) int {
	switch step {
	case ownerProjectionParent:
		return 0
	case ownerProjectionCreateCredentials, ownerProjectionAcknowledgeCredentials:
		return 1
	default:
		return 2
	}
}
func ownerProjectionStepResult(step ownerProjectionStep) OwnerProjectionAdvanceStatus {
	switch step {
	case ownerProjectionParent, ownerProjectionAcknowledgeCredentials, ownerProjectionAcknowledgeConfiguration:
		return OwnerProjectionAdvanceAcknowledged
	case ownerProjectionCreateCredentials, ownerProjectionCreateConfiguration, ownerProjectionLaunch:
		return OwnerProjectionAdvancePending
	case ownerProjectionAcknowledgeJoint, ownerProjectionReadComplete, ownerProjectionAcknowledgeLaunch, ownerProjectionReadLaunch:
		return OwnerProjectionAdvanceComplete
	default:
		return ""
	}
}
func (s *ProviderOwnerProjection) isSplit() bool {
	if s == nil || s.self != s {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.split
}

// Execute and ExecuteLaunch retain all original admission, postclaim/postlock,
// role and effect checks. Their only successful outcome is unverified work.
// Finalize is mandatory before this same controller can start another step.
func (s *ProviderOwnerProjection) Execute(ctx context.Context) error { return s.execute(ctx, false) }
func (s *ProviderOwnerProjection) ExecuteLaunch(ctx context.Context) error {
	return s.execute(ctx, true)
}
func (s *ProviderOwnerProjection) execute(ctx context.Context, launch bool) error {
	if s == nil || s.self != s || s.projection == nil || ctx == nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	if _, ok := s.verification.(OwnerProjectionFinalizationVerification); !ok {
		return cfg.ErrUnavailable
	}
	root := s.projection.root
	root.mu.Lock()
	if root.closed || root.busy || root.ctx.Err() != nil || !root.createAttempted || root.operationRootUID == "" || root.pendingOperationRoot != nil || root.splitProjection != nil && root.splitProjection != s {
		root.mu.Unlock()
		return cfg.ErrUnavailable
	}
	root.resources.mu.Lock()
	if root.resources.closed || root.resources.ctx.Err() != nil || root.resources.ownerProjectionRoot != nil && root.resources.ownerProjectionRoot != root {
		root.resources.mu.Unlock()
		root.mu.Unlock()
		return cfg.ErrUnavailable
	}
	root.resources.ownerProjectionRoot = root
	root.resources.mu.Unlock()
	root.splitProjection = s
	root.mu.Unlock()
	s.mu.Lock()
	if s.inFlight || s.pending != nil {
		s.mu.Unlock()
		return cfg.ErrUnavailable
	}
	s.split, s.inFlight, s.executionCaller = true, true, ctx
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.inFlight = false; s.executionCaller = nil; s.mu.Unlock() }()
	out, err := s.advanceMode(context.WithValue(ctx, ownerProjectionControllerKey{}, s), launch, false, true)
	if err != nil {
		return err
	}
	if out.Status != OwnerProjectionAdvanceUnverified {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *ProviderOwnerProjection) newPending(op *OwnerProjectionOperation) *ownerProjectionPending {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.split || !s.inFlight || s.pending != nil || s.executionCaller == nil {
		return nil
	}
	// An observed receipt is historical provenance, not a new process's permit.
	// The first split phase starts only from this live root's untouched original
	// resource journal; every later phase follows its exact verified predecessor.
	if op.owner.initial.roles.UID != s.projection.root.operationRootUID {
		return nil
	}
	if s.lastVerified == nil {
		if op.resources.State.OwnerIdentity != nil || op.resources.State.OwnerLaunch != nil {
			return nil
		}
	} else if op.resources.UID != s.lastVerified.resources.UID || op.resources.ResourceVersion != s.lastVerified.resources.ResourceVersion || !equalJSON(op.resources.State, s.lastVerified.resources.State) {
		return nil
	}
	original := ownerProjectionPublicPins(op.owner.initial)
	p := &ownerProjectionPending{controller: s, caller: s.executionCaller, original: original, resources: op.resources, roles: original.roles, children: s.knownChildren}
	if c := op.resources.State.OwnerIdentity; c != nil {
		for i, child := range []*contracts.OwnerIdentityObjectAttempt{c.Credentials, c.Configuration} {
			if p.children[i] == nil && child != nil && child.Receipt != nil {
				pin := *child.Receipt
				p.children[i] = &pin
			}
		}
	}
	s.pending = p
	return p
}
func (p *ownerProjectionPending) ready() bool {
	if p == nil || p.controller == nil || p.caller == nil || p.caller.Err() != nil || ownerProjectionStepResult(p.step) == "" {
		return false
	}
	for i := 0; i < ownerProjectionRequiredChildren(p.step); i++ {
		if p.children[i] == nil || p.children[i].Object.UID == "" || p.children[i].ResourceVersion == "" {
			return false
		}
	}
	return true
}
func (p *ownerProjectionPending) originalEnd() time.Time {
	end := p.resources.State.Until
	if p.roles.State.Until.Before(end) {
		end = p.roles.State.Until
	}
	if caller, ok := p.caller.Deadline(); ok && caller.Before(end) {
		end = caller
	}
	return end
}

// A completed receipt may be inspected again with current authority. This is
// distinct from pending finalization: an unresolved or consumed failed pending
// slot always wins, and no completion inspection can enable another effect.
func (s *ProviderOwnerProjection) inspectSplit(ctx context.Context, launch bool) (OwnerProjectionAdvance, error) {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil {
		return OwnerProjectionAdvance{}, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.inFlight {
		s.mu.Unlock()
		return OwnerProjectionAdvance{}, cfg.ErrUnavailable
	}
	if s.pending != nil {
		s.mu.Unlock()
		return s.Finalize(ctx)
	}
	last := s.lastVerified
	if last == nil || last.resources.State.OwnerIdentity == nil || last.resources.State.OwnerIdentity.Receipt == nil || launch && (last.resources.State.OwnerLaunch == nil || last.resources.State.OwnerLaunch.Receipt == nil) {
		s.mu.Unlock()
		return OwnerProjectionAdvance{}, cfg.ErrUnavailable
	}
	p := *last
	p.caller, p.consumed = ctx, false
	if launch {
		p.step = ownerProjectionReadLaunch
	} else {
		p.step = ownerProjectionReadComplete
	}
	s.pending = &p
	s.mu.Unlock()
	return s.Finalize(ctx)
}
