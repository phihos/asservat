package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ConfigurationWorkerProviderReader verifies the fixed worker process and its
// actual protected sources before provider credential control. It requires no
// accepted owner SQL row: producing that row is this worker's later job.
// The native clients and their transports remain owned by the deployment.
type ConfigurationWorkerProviderReader struct {
	worker *InstalledWorkerProjectionReader
	fleet  *ProtectedFleetSettings
	owner  *OwnerConfigurationSource
	podUID string
}

func NewConfigurationWorkerProviderReader(worker *InstalledWorkerProjectionReader, podUID string) (*ConfigurationWorkerProviderReader, error) {
	if worker == nil || worker.guard == nil || !authorization.UUID(podUID) || !HubWorkerActivationBound(worker.input) || worker.input.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || worker.input.ProviderAuthentication == nil || worker.input.ProviderInputs == nil {
		return nil, cfg.ErrInvalid
	}
	in, client, probe := worker.input, worker.client, worker.guard.probe
	plan := func(g contracts.OwnerDeploymentGuard, source string) (cfg.ConfigMapAdministration, GuardPin) {
		p := cfg.ConfigMapAdministration{Name: g.Name, SourceName: source, ControlNamespace: client.control}
		for _, actor := range g.Administrators {
			p.Administrators = append(p.Administrators, cfg.KubernetesActor{Kind: actor.Kind, Name: actor.Name})
		}
		return p, GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	fp, fg := plan(in.FleetGuard, in.FleetSource.Name)
	fleetGuard, err := NewFleetConfigurationProtection(client, probe, fp, fg)
	if err != nil {
		return nil, err
	}
	fleet, err := NewProtectedFleetSettings(client, fleetGuard, in.FleetSource.Name, in.FleetSource.UID, in.InstallationID)
	if err != nil {
		return nil, err
	}
	op, og := plan(in.OwnerGuard, in.OwnerSource.Name)
	ownerGuard, err := NewOwnerConfigurationProtection(client, probe, op, og)
	if err != nil {
		return nil, err
	}
	owner, err := NewOwnerConfigurationSource(client, ownerGuard, in.OwnerSource.Name, in.OwnerSource.UID, in.InstallationID)
	if err != nil {
		return nil, err
	}
	return &ConfigurationWorkerProviderReader{worker: worker, fleet: fleet, owner: owner, podUID: podUID}, nil
}

func (s *ConfigurationWorkerProviderReader) MatchesInput(in contracts.HubWorkerDeployment) bool {
	return s != nil && s.worker != nil && HubWorkerActivationBound(in) && equalJSON(s.worker.input, in)
}

// Verify compares an independently supplied epoch with current native sources.
// Provider effects supply the concrete SQL recovery epoch; VerifyProjected uses
// only the original manifest comparison pin before SQL authentication. Neither
// argument supplies native proof, clears recovery or accepts configuration.
func (s *ConfigurationWorkerProviderReader) Verify(ctx context.Context, issuerEpoch string, manifest contracts.ConfigurationRuntimeCredentialManifest, mounted map[string][]byte) (time.Time, error) {
	if s == nil || s.worker == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(issuerEpoch) {
		return time.Time{}, cfg.ErrInvalid
	}
	operation, err := s.BeginConfigurationProviderOperation(ctx, issuerEpoch, manifest, mounted)
	if err != nil {
		return time.Time{}, err
	}
	defer operation.Close()
	return s.FinishConfigurationProviderOperation(ctx, operation)
}
