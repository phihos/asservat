package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Intent precedes actual role verification and therefore supplies no SQL or
// object-creation authority. Only its positively acknowledged in-call CAS can
// select the one CREATE after later independent SQL/native verification.
func (p *ConfigurationWorkerOperation) prepareIntent(ctx context.Context, allowNew, allowReceipt bool) (err error) {
	call, done, err := p.enterPhase(ctx, p.owner.roles, configurationWorkerPhaseInitial, configurationWorkerPhaseIntent)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	claim := p.retained.resources.State.WorkerInputs
	if claim == nil {
		if !allowNew || p.owner.attempted {
			return cfg.ErrUnavailable
		}
		now := p.owner.resources.now().UTC().Truncate(time.Microsecond)
		until := identity.Earlier(p.until, p.retained.resources.State.Until).UTC().Truncate(time.Microsecond)
		if !now.Before(until) {
			return cfg.ErrUnavailable
		}
		in := p.input.ProviderInputs
		if in == nil || p.input.ProviderAuthentication == nil {
			return cfg.ErrInvalid
		}
		next := p.retained.resources.State
		next.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: in.OperationID, PublicDigest: p.digest,
			ConfigurationRoot: in.ConfigurationRoot, ConfigurationSetupID: in.ConfigurationSetupID, SQLProjection: in.SQLProjection,
			AuditCredentials: p.input.ProviderAuthentication.AuditCredentials, ClaimedAt: now, Until: until}
		p.owner.attempted = true // Set before I/O. Uncertain CAS never admits CREATE.
		p.intentUncertain = true
		if err = p.writeResourceTransition(call, next); err != nil {
			return err
		}
		p.intentUncertain = false
		p.mu.Lock()
		p.mode, p.until = configurationWorkerEffectCreate, until
		p.mu.Unlock()
		return nil
	}
	if p.input.ProviderInputs == nil || p.input.ProviderAuthentication == nil || claim.PublicDigest != p.digest ||
		!equalJSON(configurationWorkerInputProvenance(claim), p.input.ProviderInputs) || claim.AuditCredentials != p.input.ProviderAuthentication.AuditCredentials {
		return cfg.ErrChanged
	}
	// This positive GET supplies the actual later receipt timestamp. Expiry of
	// an old CREATE permit is not a reason to invent another object or backdate.
	receipt, err := p.owner.readInput(call, p.retained.resources, p.raw)
	if err != nil {
		return err
	}
	p.observedInput = receipt
	p.mode = configurationWorkerEffectReceipt
	if !allowReceipt {
		p.mode = configurationWorkerEffectObservePending
	}
	if claim.Receipt != nil {
		p.mode = configurationWorkerEffectInspect
	}
	return nil
}

// ApplyConfigurationWorkerEffect is invoked only by the original concrete SQL
// verifier after its named post-lock read and exact three-role verification.
// The handle is never returned by the installer API and cannot be constructed
// outside this package. An existing/uncertain claim can never select CREATE.
func (p *ConfigurationWorkerOperation) ApplyConfigurationWorkerEffect(ctx context.Context, root *ConfigurationRuntimeRoleRoot, verified contracts.ConfigurationRuntimeRoleSnapshot) (err error) {
	call, done, err := p.enterPhase(ctx, root, configurationWorkerPhasePostLock, configurationWorkerPhaseEffect)
	if err != nil {
		return err
	}
	defer func() { done(err) }()
	if verified.UID != p.roles.UID || verified.ResourceVersion != p.roles.ResourceVersion || !equalJSON(verified.State, p.roles.State) ||
		!configurationRoleSameSources(verified.Sources, p.roles.Sources) || !p.owner.resources.now().Before(verified.ValidUntil) ||
		p.input.ProviderAuthentication == nil || !p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now()) {
		return cfg.ErrUnavailable
	}
	call, stop := context.WithDeadline(call, verified.ValidUntil)
	defer stop()
	switch p.mode {
	case configurationWorkerEffectCreate:
		p.effectAttempted = true
		if err = p.owner.createInput(call, p.retained.resources, p.raw); err != nil {
			return err
		}
		p.observedInput, err = p.owner.readInput(call, p.retained.resources, p.raw)
		return err
	case configurationWorkerEffectReceipt:
		old := p.retained.resources.State.WorkerInputs
		if old == nil || old.Receipt != nil || p.observedInput.Configuration.UID == "" {
			return cfg.ErrChanged
		}
		claim := *old
		claim.Receipt = &p.observedInput
		next := p.retained.resources.State
		next.WorkerInputs = &claim
		p.receiptAttempted = true
		return p.writeResourceTransition(call, next)
	case configurationWorkerEffectObservePending:
		if old := p.retained.resources.State.WorkerInputs; old == nil || old.Receipt != nil || p.observedInput.Configuration.UID == "" {
			return cfg.ErrChanged
		}
		return nil
	case configurationWorkerEffectInspect:
		if old := p.retained.resources.State.WorkerInputs; old == nil || old.Receipt == nil || *old.Receipt != p.observedInput {
			return cfg.ErrChanged
		}
		return nil
	default:
		return cfg.ErrUnavailable
	}
}

// One UID/RV CAS only. Named operation boundaries own the native/SQL proof;
// this helper performs no hidden recursive current reads and admits no retry.
func (p *ConfigurationWorkerOperation) writeResourceTransition(ctx context.Context, next contracts.InitialRuntimeResourceState) error {
	old, object := p.retained.resources, p.retained.object
	if object == nil || string(object.UID) != old.UID || object.ResourceVersion != old.ResourceVersion ||
		!configurationWorkerInputTransition(old.State, next) || !p.owner.resources.valid(next) {
		return cfg.ErrChanged
	}
	until := identity.Earlier(p.until, old.State.Until)
	if p.input.ProviderAuthentication == nil || !p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now()) ||
		initialHandoverDeadline(ctx, p.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > contracts.InitialRuntimeResourcesMaxBytes {
		return cfg.ErrInvalid
	}
	body := object.DeepCopy()
	body.Data = map[string][]byte{"state.json": raw}
	reply, err := p.owner.roles.client.api.Put().AbsPath(p.owner.resources.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).DoRaw(call)
	defer clear(reply)
	if err != nil {
		return cfg.ErrUnavailable
	}
	got, observed, err := p.owner.resources.decode(call, reply)
	if err != nil {
		return err
	}
	if got.UID != old.UID || got.ResourceVersion == old.ResourceVersion || !equalJSON(got.State, next) {
		return cfg.ErrChanged
	}
	if initialHandoverDeadline(call, p.owner.resources.now, until) != nil {
		return cfg.ErrUnavailable
	}
	p.retained.resources, p.retained.object = got, observed
	return nil
}
