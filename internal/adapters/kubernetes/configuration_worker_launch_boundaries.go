package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Two fixed independent branches of a genuine launch bracket. Every started
// branch is joined. This helper returns actual responses, never a reader backed
// by a prior proof. It is used only at the initial and final named phases.
func (p *ConfigurationWorkerLaunchOperation) nativeBracket(ctx context.Context) (configurationWorkerNative, initialRuntimeRetainedResources, error) {
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	var native configurationWorkerNative
	var retained initialRuntimeRetainedResources
	var failures [2]error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() {
		defer joined.Done()
		native, failures[0] = p.worker.owner.roles.source.readConfigurationWorkerNative(call)
		if failures[0] != nil {
			cancel()
		}
	}()
	go func() {
		defer joined.Done()
		retained, failures[1] = p.worker.owner.bridge.readRetainedOriginalResources(call, p.worker.owner.resources)
		if failures[1] != nil {
			cancel()
		}
	}()
	joined.Wait()
	for _, err := range failures {
		if err != nil {
			return native, retained, err
		}
	}
	return native, retained, nil
}

func (p *ConfigurationWorkerLaunchOperation) readInitial(ctx context.Context) (err error) {
	w := p.worker
	call, done, err := p.enter(ctx, w.owner.roles, configurationWorkerPhaseUninitialized, configurationWorkerPhaseInitial)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	native, retained, err := p.nativeBracket(call)
	if err != nil {
		return err
	}
	until := identity.Earlier(w.until, identity.Earlier(native.proof.observation.FreshUntil, retained.until))
	call, cancel := context.WithDeadline(call, until)
	defer cancel()
	if !w.owner.sameOriginalResources(retained.resources) || retained.resources.UID != w.seed.resources.UID || !equalJSON(retained.resources.State, w.seed.resources.State) {
		return cfg.ErrChanged
	}
	roles, object, err := w.owner.roles.readObserved(call, native.proof.observation, native.proof.observation.ObservedAt)
	if err != nil {
		return err
	}
	keepRole := false
	defer func() {
		if !keepRole && object != nil {
			clearRuntimeProjection(object.Data)
		}
	}()
	if !w.seed.matchesRole(roles) {
		return cfg.ErrChanged
	}
	account, err := w.owner.readWorkerOperationOwnerAccount(call, native)
	if err != nil {
		return err
	}
	if err = w.owner.readWorkerOperationProjection(call, roles); err != nil {
		return err
	}
	audit, err := w.owner.readWorkerOperationAudit(call, w.input)
	if err != nil {
		return err
	}
	keepAudit := false
	defer func() {
		if !keepAudit {
			clearRuntimeProjection(audit.Data)
		}
	}()
	child := retained.resources.State.WorkerInputs
	if child == nil || child.Receipt == nil || w.input.ProviderInputs == nil {
		return cfg.ErrUnavailable
	}
	actual, digest, raw, err := w.owner.resources.configurationWorkerInputMaterial(retained.resources, roles, child.OperationID, w.owner.resources.now())
	if err != nil {
		return err
	}
	if digest != w.digest || !equalJSON(actual, w.input) || string(raw) != string(w.raw) {
		return cfg.ErrChanged
	}
	receipt, err := w.owner.readInput(call, retained.resources, w.raw)
	if err != nil {
		return err
	}
	if receipt != *child.Receipt {
		return cfg.ErrChanged
	}
	if w.input.ProviderAuthentication == nil || !w.setup.Matches(w.input, *w.input.ProviderAuthentication, w.owner.resources.now()) || initialHandoverDeadline(call, w.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	w.mu.Lock()
	w.until = until
	w.native, w.retained, w.roles, w.ownerAccount, w.audit = native, retained, roles, account, audit
	w.observedInput = receipt
	w.mu.Unlock()
	p.roleObject = object
	keepRole, keepAudit = true, true
	if roles.State.Launch != nil {
		return p.observeRunning(native, roles)
	}
	return nil
}

// ReadConfigurationWorkerLaunchPostLock performs the actual current12 source
// reads plus owner account, role journal, SQL projection and audit material.
// The public resource journal is independently read through its original
// creator client. The earlier native observations retain their original times.
func (p *ConfigurationWorkerLaunchOperation) ReadConfigurationWorkerLaunchPostLock(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (out contracts.ConfigurationRuntimeRoleSnapshot, err error) {
	call, done, err := p.enter(ctx, root, configurationWorkerPhaseIntent, configurationWorkerPhasePostLock)
	if err != nil {
		return out, err
	}
	defer func() { done(err) }()
	w := p.worker
	native, err := root.source.readConfigurationWorkerCurrent(call, w.native)
	if err != nil {
		return out, err
	}
	account, err := w.owner.readWorkerOperationOwnerAccount(call, native)
	if err != nil {
		return out, err
	}
	if !equalJSON(account, w.ownerAccount) {
		return out, cfg.ErrChanged
	}
	roles, object, err := root.readObserved(call, native.proof.observation, w.roles.ObservedAt)
	if err != nil {
		return out, err
	}
	keepRole := false
	defer func() {
		if !keepRole && object != nil {
			clearRuntimeProjection(object.Data)
		}
	}()
	if roles.UID != w.roles.UID || roles.ResourceVersion != w.roles.ResourceVersion || !equalJSON(roles.State, w.roles.State) || !configurationRoleSameSources(roles.Sources, w.roles.Sources) {
		return out, cfg.ErrChanged
	}
	if err = w.owner.readWorkerOperationProjection(call, roles); err != nil {
		return out, err
	}
	audit, err := w.owner.readWorkerOperationAudit(call, w.input)
	if err != nil {
		return out, err
	}
	defer clearRuntimeProjection(audit.Data)
	if !equalJSON(audit, w.audit) {
		return out, cfg.ErrChanged
	}
	resources, resourceObject, err := w.owner.resources.read(call)
	if err != nil {
		return out, err
	}
	if resources.UID != w.retained.resources.UID || resources.ResourceVersion != w.retained.resources.ResourceVersion || !equalJSON(resources.State, w.retained.resources.State) {
		return out, cfg.ErrChanged
	}
	until := identity.Earlier(w.until, identity.Earlier(roles.ValidUntil, resources.ValidUntil))
	if w.input.ProviderAuthentication == nil || !w.setup.Matches(w.input, *w.input.ProviderAuthentication, w.owner.resources.now()) || initialHandoverDeadline(call, w.owner.resources.now, until) != nil {
		return out, cfg.ErrUnavailable
	}
	if p.mode != configurationWorkerLaunchUpdate {
		if err = p.observeRunning(native, roles); err != nil {
			return out, err
		}
	}
	if p.roleObject != nil {
		clearRuntimeProjection(p.roleObject.Data)
	}
	p.roleObject = object
	keepRole = true
	w.mu.Lock()
	w.until = until
	w.retained.resources, w.retained.object = resources, resourceObject
	w.mu.Unlock()
	roles.ValidUntil = until
	return roles, nil
}

// ReadConfigurationWorkerLaunchFinal makes a new real native/retained bracket
// after the one update or receipt CAS. Only the original recorded zero-to-one
// spec is an allowed worker difference. Other source/material changes fail.
func (p *ConfigurationWorkerLaunchOperation) ReadConfigurationWorkerLaunchFinal(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (out contracts.ConfigurationRuntimeRoleSnapshot, err error) {
	call, done, err := p.enter(ctx, root, configurationWorkerPhaseEffect, configurationWorkerPhaseFinal)
	if err != nil {
		return out, err
	}
	defer func() { done(err) }()
	w := p.worker
	native, retained, err := p.nativeBracket(call)
	if err != nil {
		return out, err
	}
	if native.proof.guards != w.native.proof.guards || native.fleetRef != w.native.fleetRef || native.ownerRef != w.native.ownerRef ||
		!equalJSON(native.administrator, w.native.administrator) || !equalJSON(native.account, w.native.account) ||
		!equalJSON(native.ownerDeployment.Spec, w.native.ownerDeployment.Spec) || retained.bridge.UID != w.retained.bridge.UID ||
		!equalJSON(retained.bridge.State, w.retained.bridge.State) || retained.resources.UID != w.retained.resources.UID ||
		retained.resources.ResourceVersion != w.retained.resources.ResourceVersion || !equalJSON(retained.resources.State, w.retained.resources.State) {
		return out, cfg.ErrChanged
	}
	until := identity.Earlier(w.until, identity.Earlier(native.proof.observation.FreshUntil, retained.until))
	call, cancel := context.WithDeadline(call, until)
	defer cancel()
	account, err := w.owner.readWorkerOperationOwnerAccount(call, native)
	if err != nil {
		return out, err
	}
	if !equalJSON(account, w.ownerAccount) {
		return out, cfg.ErrChanged
	}
	roles, object, err := root.readObserved(call, native.proof.observation, w.roles.ObservedAt)
	if err != nil {
		return out, err
	}
	if object != nil {
		defer clearRuntimeProjection(object.Data)
	}
	if roles.UID != w.roles.UID || roles.ResourceVersion != w.roles.ResourceVersion || !equalJSON(roles.State, w.roles.State) {
		return out, cfg.ErrChanged
	}
	original, ok := configurationWorkerOriginalLaunchSources(native.proof.observation, native.deployment, roles)
	if !ok || !configurationWorkerLaunchMetadataMatches(native.deployment, w.native.deployment, roles.State.Launch) || !configurationRoleSameSources(original, roles.State.Launch.Sources) {
		return out, cfg.ErrChanged
	}
	if err = w.owner.readWorkerOperationProjection(call, roles); err != nil {
		return out, err
	}
	audit, err := w.owner.readWorkerOperationAudit(call, w.input)
	if err != nil {
		return out, err
	}
	defer clearRuntimeProjection(audit.Data)
	if !equalJSON(audit, w.audit) {
		return out, cfg.ErrChanged
	}
	receipt, err := w.owner.readInput(call, retained.resources, w.raw)
	if err != nil {
		return out, err
	}
	if receipt != w.observedInput {
		return out, cfg.ErrChanged
	}
	if w.input.ProviderAuthentication == nil || !w.setup.Matches(w.input, *w.input.ProviderAuthentication, w.owner.resources.now()) || initialHandoverDeadline(call, w.owner.resources.now, until) != nil {
		return out, cfg.ErrUnavailable
	}
	w.mu.Lock()
	w.until = until
	w.retained = retained
	w.mu.Unlock()
	if err = p.observeRunning(native, roles); err != nil {
		return out, err
	}
	roles.ValidUntil = until
	w.roles = roles
	return roles, nil
}
