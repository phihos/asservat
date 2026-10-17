package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// The initial native/retained bracket runs under the independent outer bridge
// recovery/activation locks, before public intent and before SQL role locks.
// It is not the untrusted seed and does not claim SQL role verification.
func (p *ConfigurationWorkerOperation) readInitial(ctx context.Context) (err error) {
	call, done, err := p.enterPhase(ctx, p.owner.roles, configurationWorkerPhaseUninitialized, configurationWorkerPhaseInitial)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	batch, stop := context.WithCancel(call)
	defer stop()
	var native configurationWorkerNative
	var retained initialRuntimeRetainedResources
	var failures [2]error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() {
		defer joined.Done()
		native, failures[0] = p.owner.roles.source.readConfigurationWorkerNative(batch)
		if failures[0] != nil {
			stop()
		}
	}()
	go func() {
		defer joined.Done()
		retained, failures[1] = p.owner.bridge.readRetainedOriginalResources(batch, p.owner.resources)
		if failures[1] != nil {
			stop()
		}
	}()
	joined.Wait()
	for _, failure := range failures {
		if failure != nil {
			return failure
		}
	}
	until := identity.Earlier(p.until, identity.Earlier(native.proof.observation.FreshUntil, retained.until))
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	if !p.owner.sameOriginalResources(retained.resources) || retained.resources.UID != p.seed.resources.UID || !equalJSON(retained.resources.State, p.seed.resources.State) {
		return cfg.ErrChanged
	}
	roles, _, err := p.owner.roles.readObserved(call, native.proof.observation, native.proof.observation.ObservedAt)
	if err != nil {
		return err
	}
	if !p.seed.matchesRole(roles) || roles.State.Launch != nil {
		return cfg.ErrChanged
	}
	ownerAccount, err := p.owner.readWorkerOperationOwnerAccount(call, native)
	if err != nil {
		return err
	}
	if err = p.owner.readWorkerOperationProjection(call, roles); err != nil {
		return err
	}
	audit, err := p.owner.readWorkerOperationAudit(call, p.input)
	if err != nil {
		return err
	}
	keepAudit := false
	defer func() {
		if !keepAudit {
			clearRuntimeProjection(audit.Data)
		}
	}()
	actual, digest, raw, err := p.owner.resources.configurationWorkerInputMaterial(retained.resources, roles, p.input.ProviderInputs.OperationID, p.owner.resources.now())
	if err != nil {
		return err
	}
	if digest != p.digest || !equalJSON(actual, p.input) || string(raw) != string(p.raw) {
		return cfg.ErrChanged
	}
	if p.input.ProviderAuthentication == nil || !p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now()) || initialHandoverDeadline(call, p.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	p.mu.Lock()
	p.until = until
	p.native, p.retained, p.roles, p.ownerAccount, p.audit = native, retained, roles, ownerAccount, audit
	p.mu.Unlock()
	keepAudit = true
	return nil
}

// ReadConfigurationWorkerPostLock is called by the concrete PostgreSQL
// verifier only after its recovery/advisory locks. It performs all sixteen
// actual current observer reads plus the exact resource journal read. The
// expected root pointer/context/phase are independently pinned by that verifier;
// retained native facts cannot substitute for any of these current values.
func (p *ConfigurationWorkerOperation) ReadConfigurationWorkerPostLock(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (out contracts.ConfigurationRuntimeRoleSnapshot, err error) {
	call, done, err := p.enterPhase(ctx, root, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock)
	if err != nil {
		return out, err
	}
	defer func() { done(err) }()
	native, err := root.source.readConfigurationWorkerCurrent(call, p.native)
	if err != nil {
		return out, err
	}
	ownerAccount, err := p.owner.readWorkerOperationOwnerAccount(call, native)
	if err != nil {
		return out, err
	}
	if !equalJSON(ownerAccount, p.ownerAccount) {
		return out, cfg.ErrChanged
	}
	roles, _, err := root.readObserved(call, native.proof.observation, p.roles.ObservedAt)
	if err != nil {
		return out, err
	}
	if roles.UID != p.roles.UID || roles.ResourceVersion != p.roles.ResourceVersion || !equalJSON(roles.State, p.roles.State) || !configurationRoleSameSources(roles.Sources, p.roles.Sources) {
		return out, cfg.ErrChanged
	}
	if err = p.owner.readWorkerOperationProjection(call, roles); err != nil {
		return out, err
	}
	audit, err := p.owner.readWorkerOperationAudit(call, p.input)
	if err != nil {
		return out, err
	}
	defer clearRuntimeProjection(audit.Data)
	if !equalJSON(audit, p.audit) {
		return out, cfg.ErrChanged
	}
	resources, object, err := p.owner.resources.read(call)
	if err != nil {
		return out, err
	}
	if resources.UID != p.retained.resources.UID || resources.ResourceVersion != p.retained.resources.ResourceVersion || !equalJSON(resources.State, p.retained.resources.State) {
		return out, cfg.ErrChanged
	}
	until := identity.Earlier(p.until, identity.Earlier(roles.ValidUntil, resources.ValidUntil))
	if p.input.ProviderAuthentication == nil || !p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now()) || initialHandoverDeadline(call, p.owner.resources.now, until) != nil {
		return out, cfg.ErrUnavailable
	}
	p.mu.Lock()
	p.until = until
	p.retained.resources, p.retained.object = resources, object
	p.mu.Unlock()
	roles.ValidUntil = until
	return roles, nil
}
