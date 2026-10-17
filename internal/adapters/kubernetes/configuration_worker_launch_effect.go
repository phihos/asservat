package kubernetes

import (
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	apps "k8s.io/api/apps/v1"
)

func (p *ConfigurationWorkerLaunchOperation) prepareIntent(ctx context.Context, allowNew, allowReceipt bool) (err error) {
	w := p.worker
	call, done, err := p.enter(ctx, w.owner.roles, configurationWorkerPhaseInitial, configurationWorkerPhaseIntent)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	if w.roles.State.Launch == nil {
		if !allowNew || w.owner.launchAttempted {
			return cfg.ErrUnavailable
		}
		plan, e := configurationWorkerLaunchPlanFor(w.input, w.retained.resources, w.roles, w.native.deployment, uuid.NewString(), w.owner.resources.now(), w.until)
		if e != nil {
			return e
		}
		p.plan = plan
		next := w.roles.State
		next.Launch = &plan.claim
		w.owner.launchAttempted = true
		p.intentUncertain = true
		if err = p.writeRoleTransition(call, next); err != nil {
			return err
		}
		p.intentUncertain = false
		p.mode = configurationWorkerLaunchUpdate
		w.mu.Lock()
		w.until = identity.Earlier(w.until, plan.claim.Until)
		w.mu.Unlock()
		return nil
	}
	if err = p.observeRunning(w.native, w.roles); err != nil {
		return err
	}
	p.mode = configurationWorkerLaunchReceipt
	if !allowReceipt {
		p.mode = configurationWorkerLaunchObservePending
	}
	if w.roles.State.Launch.Receipt != nil {
		p.mode = configurationWorkerLaunchInspect
	}
	return nil
}

// The role journal may acquire exactly one immutable launch claim, or the first
// positive receipt for that same claim. Every other original byte is retained.
func configurationWorkerLaunchTransition(old, next contracts.ConfigurationRuntimeRoleState) bool {
	a, b := old.Launch, next.Launch
	if b == nil {
		return false
	}
	if a != nil {
		if a.Receipt != nil || b.Receipt == nil {
			return false
		}
		aa, bb := *a, *b
		aa.Receipt = nil
		bb.Receipt = nil
		if !equalJSON(aa, bb) {
			return false
		}
	} else if b.Receipt != nil {
		return false
	}
	old.Launch = nil
	next.Launch = nil
	return equalJSON(old, next)
}

func (p *ConfigurationWorkerLaunchOperation) writeRoleTransition(ctx context.Context, next contracts.ConfigurationRuntimeRoleState) error {
	w := p.worker
	old, object := w.roles, p.roleObject
	if object == nil || string(object.UID) != old.UID || object.ResourceVersion != old.ResourceVersion || !configurationWorkerLaunchTransition(old.State, next) ||
		!configurationRoleStateValid(w.owner.roles.input, next, w.owner.resources.now()) {
		return cfg.ErrChanged
	}
	until := identity.Earlier(w.until, identity.Earlier(old.State.Until, w.retained.resources.State.Until))
	if w.input.ProviderAuthentication == nil || !w.setup.Matches(w.input, *w.input.ProviderAuthentication, w.owner.resources.now()) || initialHandoverDeadline(ctx, w.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > contracts.ConfigurationRuntimeRoleMaxBytes {
		return cfg.ErrInvalid
	}
	defer clear(raw)
	body := object.DeepCopy()
	defer clearRuntimeProjection(body.Data)
	body.Data = map[string][]byte{"state.json": raw}
	reply, err := w.owner.roles.client.api.Put().AbsPath(w.owner.roles.path()+"/"+w.owner.roles.name()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(call)
	defer clear(reply)
	if err != nil {
		return cfg.ErrUnavailable
	}
	got, observed, err := w.owner.roles.decode(reply, old.ObservedAt, until)
	if err != nil {
		return err
	}
	good := false
	defer func() {
		if !good && observed != nil {
			clearRuntimeProjection(observed.Data)
		}
	}()
	if got.UID != old.UID || got.ResourceVersion == old.ResourceVersion || !equalJSON(got.State, next) {
		return cfg.ErrChanged
	}
	if initialHandoverDeadline(call, w.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	got.Sources = old.Sources
	got.Sources.FreshUntil = identity.Earlier(got.Sources.FreshUntil, until)
	clearRuntimeProjection(object.Data)
	p.roleObject = observed
	w.roles = got
	good = true
	return nil
}

// ApplyConfigurationWorkerLaunchEffect is a single named effect under the
// concrete role producer's locks. A persisted/unknown launch can only inspect
// or acknowledge history; only the positively acknowledged in-call intent can
// select the original Deployment PUT.
func (p *ConfigurationWorkerLaunchOperation) ApplyConfigurationWorkerLaunchEffect(ctx context.Context, root *ConfigurationRuntimeRoleRoot, verified contracts.ConfigurationRuntimeRoleSnapshot) (err error) {
	call, done, err := p.enter(ctx, root, configurationWorkerPhasePostLock, configurationWorkerPhaseEffect)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	w := p.worker
	if verified.UID != w.roles.UID || verified.ResourceVersion != w.roles.ResourceVersion || !equalJSON(verified.State, w.roles.State) ||
		!configurationRoleSameSources(verified.Sources, w.roles.Sources) || !w.owner.resources.now().Before(verified.ValidUntil) ||
		w.input.ProviderAuthentication == nil || !w.setup.Matches(w.input, *w.input.ProviderAuthentication, w.owner.resources.now()) {
		return cfg.ErrUnavailable
	}
	call, cancel := context.WithDeadline(call, verified.ValidUntil)
	defer cancel()
	// This actual pre-effect read cannot be replaced by the initial immutable
	// object or the stored receipt. It proves the same original mount still exists.
	receipt, err := w.owner.readInput(call, w.retained.resources, w.raw)
	if err != nil {
		return err
	}
	if receipt != w.observedInput {
		return cfg.ErrChanged
	}
	switch p.mode {
	case configurationWorkerLaunchUpdate:
		claim := w.roles.State.Launch
		if claim == nil || claim.Receipt != nil || !equalJSON(*claim, p.plan.claim) || p.plan.running.ResourceVersion != claim.InertResourceVersion ||
			w.native.deployment.ResourceVersion != claim.InertResourceVersion || !w.owner.resources.now().Before(claim.Until) {
			return cfg.ErrUnavailable
		}
		call, stop := context.WithDeadline(call, claim.Until)
		defer stop()
		p.effectAttempted = true
		reply, e := root.client.api.Put().AbsPath("/apis/apps/v1/namespaces/"+root.input.Namespace.Name+"/deployments/"+root.input.Deployment.Name).Param("fieldValidation", "Strict").MaxRetries(0).Body(&p.plan.running).DoRaw(call)
		if e != nil {
			return cfg.ErrUnavailable
		}
		var running apps.Deployment
		if permissionJSON(reply, permissionPageBytes, 131072) != nil || strictGuardJSON(reply, &running) != nil || running.APIVersion != "apps/v1" || running.Kind != "Deployment" ||
			!configurationLaunchSpec(running, root.input, claim) || !equalJSON(running.Labels, p.plan.running.Labels) || !equalJSON(running.Annotations, p.plan.running.Annotations) ||
			!equalJSON(running.OwnerReferences, p.plan.running.OwnerReferences) {
			return cfg.ErrChanged
		}
		return initialHandoverDeadline(call, w.owner.resources.now, claim.Until)
	case configurationWorkerLaunchReceipt:
		old := w.roles.State.Launch
		if old == nil || old.Receipt != nil || p.observed.ResourceVersion == "" {
			return cfg.ErrChanged
		}
		launch := *old
		launch.Receipt = &p.observed
		next := w.roles.State
		next.Launch = &launch
		p.receiptAttempted = true
		return p.writeRoleTransition(call, next)
	case configurationWorkerLaunchInspect:
		if old := w.roles.State.Launch; old == nil || old.Receipt == nil || *old.Receipt != p.observed {
			return cfg.ErrChanged
		}
		return nil
	case configurationWorkerLaunchObservePending:
		if old := w.roles.State.Launch; old == nil || old.Receipt != nil || p.observed.ResourceVersion == "" {
			return cfg.ErrChanged
		}
		return nil
	default:
		return cfg.ErrUnavailable
	}
}

func (p *ConfigurationWorkerLaunchOperation) CompleteConfigurationWorkerLaunch(ctx context.Context, root *ConfigurationRuntimeRoleRoot) (err error) {
	_, done, err := p.enter(ctx, root, configurationWorkerPhaseFinal, configurationWorkerPhaseJoined)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	progress := ConfigurationWorkerLaunchPending
	if p.mode != configurationWorkerLaunchUpdate && p.mode != configurationWorkerLaunchObservePending {
		claim := p.worker.roles.State.Launch
		if claim == nil || claim.Receipt == nil || *claim.Receipt != p.observed {
			return cfg.ErrChanged
		}
		progress = ConfigurationWorkerLaunchAcknowledged
	}
	p.result = ConfigurationWorkerLaunchAdvance{Progress: progress, Snapshot: p.worker.roles}
	return nil
}
