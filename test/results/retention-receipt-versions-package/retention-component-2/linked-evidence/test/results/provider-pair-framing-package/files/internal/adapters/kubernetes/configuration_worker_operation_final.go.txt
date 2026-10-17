package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// ReadConfigurationWorkerFinal performs a new genuine independent native
// bracket after the single effect. No earlier denial response is reused here.
// It still ends within the first provider/caller/native/SQL interval.
func (p *ConfigurationWorkerOperation) ReadConfigurationWorkerFinal(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (out contracts.ConfigurationRuntimeRoleSnapshot, err error) {
	call, done, err := p.enterPhase(ctx, root, configurationWorkerPhaseEffect, configurationWorkerPhaseFinal)
	if err != nil {
		return out, err
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
		native, failures[0] = root.source.readConfigurationWorkerNative(batch)
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
			return out, failure
		}
	}
	if !configurationRoleSameSources(native.proof.observation, p.native.proof.observation) ||
		native.proof.guards != p.native.proof.guards || native.fleetRef != p.native.fleetRef || native.ownerRef != p.native.ownerRef ||
		!equalJSON(native.administrator, p.native.administrator) || !equalJSON(native.account, p.native.account) ||
		native.deployment.ResourceVersion != p.native.deployment.ResourceVersion || !equalJSON(native.deployment.Spec, p.native.deployment.Spec) ||
		!equalJSON(native.ownerDeployment.Spec, p.native.ownerDeployment.Spec) ||
		retained.bridge.UID != p.retained.bridge.UID || !equalJSON(retained.bridge.State, p.retained.bridge.State) ||
		retained.resources.UID != p.retained.resources.UID || retained.resources.ResourceVersion != p.retained.resources.ResourceVersion || !equalJSON(retained.resources.State, p.retained.resources.State) {
		return out, cfg.ErrChanged
	}
	until := identity.Earlier(p.until, identity.Earlier(native.proof.observation.FreshUntil, retained.until))
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
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
	receipt, err := p.owner.readInput(call, retained.resources, p.raw)
	if err != nil {
		return out, err
	}
	if receipt.Configuration != p.observedInput.Configuration || receipt.ResourceVersion != p.observedInput.ResourceVersion {
		return out, cfg.ErrChanged
	}
	if p.input.ProviderAuthentication == nil || !p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now()) || initialHandoverDeadline(call, p.owner.resources.now, until) != nil {
		return out, cfg.ErrUnavailable
	}
	p.mu.Lock()
	p.until = until
	p.retained = retained
	p.mu.Unlock()
	roles.ValidUntil = until
	return roles, nil
}

// Complete is called only after the actual SQL verifier's final source and
// incarnation checks and successful transaction completion. It cannot turn an
// expired final read, uncertain SQL reply or a CREATE into a positive receipt.
func (p *ConfigurationWorkerOperation) CompleteConfigurationWorkerOperation(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (err error) {
	_, done, err := p.enterPhase(ctx, root, configurationWorkerPhaseFinal, configurationWorkerPhaseJoined)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	progress := ConfigurationWorkerInputPending
	if p.mode != configurationWorkerEffectCreate && p.mode != configurationWorkerEffectObservePending {
		claim := p.retained.resources.State.WorkerInputs
		if claim == nil || claim.Receipt == nil || *claim.Receipt != p.observedInput {
			return cfg.ErrChanged
		}
		progress = ConfigurationWorkerInputAcknowledged
	}
	p.result = ConfigurationWorkerInputAdvance{Progress: progress, Snapshot: p.retained.resources}
	return nil
}
