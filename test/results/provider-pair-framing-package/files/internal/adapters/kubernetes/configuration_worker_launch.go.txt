package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
)

// This private value is made only after the concrete original SQL inventory and
// external read-only provider inspection. It cannot refresh its setup interval,
// select a different deployment or stand in for qualified storage installation.
type configurationWorkerLaunchCheck struct {
	owner     *ConfigurationWorkerInputs
	resources contracts.InitialRuntimeResourceSnapshot
	input     contracts.HubWorkerDeployment
	digest    string
	setup     providerconfig.ConfigurationSetupCheck
}

func (p *configurationWorkerLaunchCheck) current(ctx context.Context) bool {
	return p != nil && p.owner != nil && ctx != nil && ctx.Err() == nil && p.input.ProviderAuthentication != nil && p.input.ProviderInputs != nil &&
		p.setup.Matches(p.input, *p.input.ProviderAuthentication, p.owner.resources.now())
}

func (p *configurationWorkerLaunchCheck) before(ctx context.Context, root *ConfigurationRuntimeRoleRoot, candidate contracts.ConfigurationRuntimeRoleSnapshot, running apps.Deployment) error {
	if !p.current(ctx) || p.owner.roles != root || candidate.State.Launch == nil {
		return cfg.ErrUnavailable
	}
	current, _, err := p.owner.readResources(ctx)
	if err != nil {
		return err
	}
	if current.UID != p.resources.UID || !equalJSON(current.State, p.resources.State) {
		return cfg.ErrChanged
	}
	input, digest, _, err := p.owner.resources.configurationWorkerInputMaterial(current, candidate, p.input.ProviderInputs.OperationID, p.owner.resources.now())
	if err != nil {
		return err
	}
	if digest != p.digest || !equalJSON(input, p.input) {
		return cfg.ErrChanged
	}
	decoded, object, err := root.readConfigurationLaunchInput(ctx, candidate)
	if err != nil {
		return err
	}
	if !equalJSON(decoded, input) {
		return cfg.ErrChanged
	}
	if err = root.configurationProviderLaunchedInputs(ctx, candidate, running, decoded, object); err != nil {
		return err
	}
	if !p.current(ctx) {
		return cfg.ErrUnavailable
	}
	return nil
}

// Launch performs only the first acknowledged original zero-to-one effect.
// Missing publication, an existing launch claim or an unknown prior effect does
// not recreate inputs or admit another UPDATE. A fresh independent read through
// AcknowledgeLaunch records the original result after its SQL/native readback.
func (s *ConfigurationWorkerInputs) Launch(ctx context.Context) error {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer finish()
	call, release, err := s.resources.borrowWorkerProjection(call)
	if err != nil {
		return err
	}
	defer release()
	return s.roles.WithConfigurationRoleOperation(call, func(live context.Context) error {
		verified, err := s.verification.VerifyConfigurationRuntimeRoles(live)
		if err != nil {
			return err
		}
		if verified.State.Launch != nil || verified.State.Input != s.roles.input {
			return cfg.ErrChanged
		}
		live, end := context.WithDeadline(live, verified.ValidUntil)
		defer end()
		provisional, _, err := s.resources.read(live)
		if err != nil {
			return err
		}
		p := provisional.State.WorkerInputs
		if p == nil || p.Receipt == nil {
			return cfg.ErrUnavailable
		}
		input, digest, raw, err := s.resources.configurationWorkerInputMaterial(provisional, verified, p.OperationID, s.resources.now())
		if err != nil {
			return err
		}
		if p.PublicDigest != digest {
			return cfg.ErrChanged
		}
		// Provider GETs finish before the bridge's bounded SQL/Kubernetes effect
		// callback. The opaque original check is only revalidated inside it.
		setup, err := s.setup.VerifyConfiguration(live, input, *input.ProviderAuthentication)
		if err != nil {
			return err
		}
		live, narrow := context.WithDeadline(live, setup.FreshUntil())
		defer narrow()
		return s.bridge.operation(live, func(bound context.Context) error {
			current, _, err := s.readResources(bound)
			if err != nil {
				return err
			}
			if current.UID != provisional.UID || !equalJSON(current.State, provisional.State) {
				return cfg.ErrChanged
			}
			if err = s.currentRoles(bound, verified, false); err != nil {
				return err
			}
			receipt, err := s.readInput(bound, current, raw)
			if err != nil {
				return err
			}
			if receipt != *p.Receipt {
				return cfg.ErrChanged
			}
			if !setup.Matches(input, *input.ProviderAuthentication, s.resources.now()) {
				return cfg.ErrUnavailable
			}
			check := &configurationWorkerLaunchCheck{owner: s, resources: current, input: input, digest: digest, setup: setup}
			return s.roles.launchConfigurationRuntime(bound, verified, receipt.Configuration, p.AuditCredentials, check)
		})
	})
}

// AcknowledgeLaunch never issues a Deployment UPDATE. It accepts only the exact
// original launched state under independent current SQL and native checks. Lost
// claim/write replies cannot select the Launch method through this reader.
func (s *ConfigurationWorkerInputs) AcknowledgeLaunch(ctx context.Context) error {
	call, finish, err := s.enter(ctx)
	if err != nil {
		return err
	}
	defer finish()
	call, release, err := s.resources.borrowWorkerProjection(call)
	if err != nil {
		return err
	}
	defer release()
	return s.roles.WithConfigurationRoleOperation(call, func(live context.Context) error {
		verified, err := s.verification.VerifyLaunchedConfigurationRuntimeRoles(live)
		if err != nil {
			return err
		}
		if verified.State.Input != s.roles.input || verified.State.Launch == nil {
			return cfg.ErrChanged
		}
		live, end := context.WithDeadline(live, verified.ValidUntil)
		defer end()
		return s.bridge.operation(live, func(bound context.Context) error {
			current, _, err := s.readResources(bound)
			if err != nil {
				return err
			}
			p := current.State.WorkerInputs
			if p == nil || p.Receipt == nil || p.Receipt.Configuration != verified.State.Launch.Configuration || p.AuditCredentials != verified.State.Launch.Providers {
				return cfg.ErrChanged
			}
			if err = s.currentRoles(bound, verified, true); err != nil {
				return err
			}
			return s.roles.RecordConfigurationRuntimeLaunch(bound, verified)
		})
	})
}
