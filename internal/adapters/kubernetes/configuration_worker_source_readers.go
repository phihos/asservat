package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// These two fixed sources belong only to the original provider-installed worker.
// They retain independent reconciliation and actual source reads; they share no
// observation, cache, timestamp or successful proof with each other or refresh.
type ConfigurationWorkerFleetReader struct {
	provider *ConfigurationWorkerProviderReader
}
type ConfigurationWorkerOwnerReader struct {
	provider *ConfigurationWorkerProviderReader
}

var _ app.AdministrationReader = (*ConfigurationWorkerFleetReader)(nil)
var _ app.OwnerConfigurationReader = (*ConfigurationWorkerOwnerReader)(nil)

// Construction validates only original client/input bindings, not readiness.
func NewConfigurationWorkerSourceReaders(provider *ConfigurationWorkerProviderReader) (*ConfigurationWorkerFleetReader, *ConfigurationWorkerOwnerReader, error) {
	if !provider.providerClientsBound() || !HubWorkerActivationBound(provider.worker.input) || provider.worker.input.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout {
		return nil, nil, cfg.ErrInvalid
	}
	return &ConfigurationWorkerFleetReader{provider}, &ConfigurationWorkerOwnerReader{provider}, nil
}

// One plain bounded GET of the fixed source under ordinary RBAC (Helm-native
// plan, slice 0) by the worker's own client. This private
// helper cannot be retained as authority or implement a reader.
func (s *ConfigurationWorkerProviderReader) configurationSourceValue(ctx context.Context, protection *configMapProtection, ref contracts.WorkerObjectReference) (core.ConfigMap, time.Time, time.Time, error) {
	var value core.ConfigMap
	var zero time.Time
	if ctx == nil || ctx.Err() != nil || !s.providerClientsBound() ||
		!((protection == s.fleet.protection.configMapProtection && ref == s.worker.input.FleetSource) ||
			(protection == s.owner.protection.configMapProtection && ref == s.worker.input.OwnerSource)) {
		return value, zero, zero, cfg.ErrUnavailable
	}
	client := s.worker.client
	started := client.now()
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer end()
	until, _ := call.Deadline()
	if err := s.worker.get(call, "/api/v1/namespaces/"+s.worker.input.Namespace.Name+"/configmaps/"+ref.Name, &value); err != nil {
		return core.ConfigMap{}, zero, zero, err
	}
	if initialHandoverDeadline(call, client.now, until) != nil {
		return core.ConfigMap{}, zero, zero, cfg.ErrUnavailable
	}
	return value, started, until, nil
}

func (s *ConfigurationWorkerFleetReader) FleetAdministration(ctx context.Context) (fleet.Administration, error) {
	var zero fleet.Administration
	if s == nil || s.provider == nil {
		return zero, cfg.ErrUnavailable
	}
	p := s.provider
	object, started, until, err := p.configurationSourceValue(ctx, p.fleet.protection.configMapProtection, p.worker.input.FleetSource)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	data, ref, err := p.worker.client.decodeInstallationConfig(raw, p.worker.input.FleetSource.Name, p.worker.input.FleetSource.UID, false)
	if err != nil {
		return zero, err
	}
	out, err := p.fleet.settings.decodeFleetAdministration(data, ref, started)
	if err != nil || !out.Valid(p.worker.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	out.FreshUntil = identity.Earlier(until, out.FreshUntil)
	// Suspension is a valid source value which the real SQL observer must see.
	// Neither unavailable material nor a new observation can clear recovery.
	if ctx.Err() != nil || !out.Valid(p.worker.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

func (s *ConfigurationWorkerOwnerReader) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	var zero fleet.OwnerConfigurationObservation
	if s == nil || s.provider == nil {
		return zero, cfg.ErrUnavailable
	}
	p := s.provider
	object, started, until, err := p.configurationSourceValue(ctx, p.owner.protection.configMapProtection, p.worker.input.OwnerSource)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(object)
	if err != nil {
		return zero, cfg.ErrChanged
	}
	data, _, err := p.worker.client.decodeInstallationConfig(raw, p.worker.input.OwnerSource.Name, p.worker.input.OwnerSource.UID, false)
	if err != nil {
		return zero, err
	}
	decoded, rootsUntil, err := p.owner.decodeOwnerConfiguration(data)
	decoded.ProtectionDigest = p.owner.protection.digest
	if err != nil || !decoded.Valid() {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, rootsUntil)
	out := fleet.OwnerConfigurationObservation{Configuration: decoded, ObservedAt: started, FreshUntil: until}
	if ctx.Err() != nil || !out.Valid(p.worker.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
