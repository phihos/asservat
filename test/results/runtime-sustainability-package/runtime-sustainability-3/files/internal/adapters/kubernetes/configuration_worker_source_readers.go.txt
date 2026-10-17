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

// Eight observer requests and one genuine three-request native denial. The
// already-read complete probe object supplies the first value. Both guard passes
// and namespace reads remain actual; the final value follows the final guard so
// a mutation during that guard's read cannot be hidden behind the probe value.
// This private helper cannot be retained as authority or implement a reader.
func (s *ConfigurationWorkerProviderReader) configurationSourceValues(ctx context.Context, protection *configMapProtection, ref contracts.WorkerObjectReference) ([2]core.ConfigMap, time.Time, time.Time, error) {
	var values [2]core.ConfigMap
	var zero time.Time
	if ctx == nil || ctx.Err() != nil || !s.providerClientsBound() ||
		!((protection == s.fleet.protection.configMapProtection && ref == s.worker.input.FleetSource) ||
			(protection == s.owner.protection.configMapProtection && ref == s.worker.input.OwnerSource)) {
		return values, zero, zero, cfg.ErrUnavailable
	}
	client := s.worker.client
	started := client.now()
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer end()
	until, _ := call.Deadline()
	call, tokens, err := s.beginTokenInterval(call)
	if err != nil {
		return values, zero, zero, err
	}
	defer tokens.close()
	namespace, err := client.namespace(call, client.control)
	if err != nil || namespace.Deleting {
		return values, zero, zero, cfg.ErrUnavailable
	}
	before, err := checkAdmissionGuard(call, client, protection.plan.Name, protection.pin, protection.policy, protection.binding)
	if err != nil {
		return values, zero, zero, err
	}
	first, actor, err := protection.proveObjectIdentity(call)
	if err != nil {
		return values, zero, zero, err
	}
	if _, err = s.worker.configurationProviderActor(actor, s.podUID); err != nil {
		return values, zero, zero, err
	}
	after, err := checkAdmissionGuard(call, client, protection.plan.Name, protection.pin, protection.policy, protection.binding)
	if err != nil {
		return values, zero, zero, err
	}
	if after != before {
		return values, zero, zero, cfg.ErrChanged
	}
	var last core.ConfigMap
	if err = s.worker.get(call, "/api/v1/namespaces/"+s.worker.input.Namespace.Name+"/configmaps/"+ref.Name, &last); err != nil {
		return values, zero, zero, err
	}
	namespace, err = client.namespace(call, client.control)
	if err != nil || namespace.Deleting || initialHandoverDeadline(call, client.now, until) != nil {
		return values, zero, zero, cfg.ErrUnavailable
	}
	if err = tokens.mountedCurrent(call); err != nil {
		return values, zero, zero, err
	}
	return [2]core.ConfigMap{first, last}, started, until, nil
}

func (s *ConfigurationWorkerFleetReader) FleetAdministration(ctx context.Context) (fleet.Administration, error) {
	var zero fleet.Administration
	if s == nil || s.provider == nil {
		return zero, cfg.ErrUnavailable
	}
	p := s.provider
	values, started, until, err := p.configurationSourceValues(ctx, p.fleet.protection.configMapProtection, p.worker.input.FleetSource)
	if err != nil {
		return zero, err
	}
	var decoded [2]fleet.Administration
	var refs [2]cfg.Resource
	for i, object := range values {
		raw, e := json.Marshal(object)
		if e != nil {
			return zero, cfg.ErrChanged
		}
		data, ref, e := p.worker.client.decodeInstallationConfig(raw, p.worker.input.FleetSource.Name, p.worker.input.FleetSource.UID, false)
		if e != nil {
			return zero, e
		}
		refs[i] = ref
		decoded[i], e = p.fleet.settings.decodeFleetAdministration(data, ref, started)
		if e != nil || !decoded[i].Valid(p.worker.client.now()) {
			return zero, cfg.ErrUnavailable
		}
	}
	if refs[0] != refs[1] || decoded[0].Revision != decoded[1].Revision || decoded[0].InstallationID != decoded[1].InstallationID || decoded[0].IssuerEpoch != decoded[1].IssuerEpoch {
		return zero, cfg.ErrChanged
	}
	out := decoded[0]
	out.FreshUntil = identity.Earlier(until, identity.Earlier(out.FreshUntil, decoded[1].FreshUntil))
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
	values, started, until, err := p.configurationSourceValues(ctx, p.owner.protection.configMapProtection, p.worker.input.OwnerSource)
	if err != nil {
		return zero, err
	}
	var decoded [2]fleet.OwnerConfiguration
	var refs [2]cfg.Resource
	for i, object := range values {
		raw, e := json.Marshal(object)
		if e != nil {
			return zero, cfg.ErrChanged
		}
		data, ref, e := p.worker.client.decodeInstallationConfig(raw, p.worker.input.OwnerSource.Name, p.worker.input.OwnerSource.UID, false)
		if e != nil {
			return zero, e
		}
		refs[i] = ref
		var rootsUntil time.Time
		decoded[i], rootsUntil, e = p.owner.decodeOwnerConfiguration(data)
		decoded[i].ProtectionDigest = p.owner.protection.digest
		if e != nil || !decoded[i].Valid() {
			return zero, cfg.ErrUnavailable
		}
		until = identity.Earlier(until, rootsUntil)
	}
	if refs[0] != refs[1] || !decoded[0].Equal(decoded[1]) {
		return zero, cfg.ErrChanged
	}
	out := fleet.OwnerConfigurationObservation{Configuration: decoded[0], ObservedAt: started, FreshUntil: until}
	if ctx.Err() != nil || !out.Valid(p.worker.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
