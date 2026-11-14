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
