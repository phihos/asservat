package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
)

const fleetConfigurationDenial = "Asservat fleet configuration administrator is required."

type FleetConfigurationProtection struct{ *configMapProtection }

func FleetConfigurationAdmission(p cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	return configMapAdmission(p, "protected-fleet-namespace", fleetConfigurationDenial)
}

func NewFleetConfigurationProtection(observer, probe *PermissionClient, plan cfg.ConfigMapAdministration, pin GuardPin) (*FleetConfigurationProtection, error) {
	g, err := newConfigMapProtection(observer, probe, plan, pin, "protected-fleet-namespace", fleetConfigurationDenial)
	if err != nil {
		return nil, err
	}
	return &FleetConfigurationProtection{g}, nil
}

// ProtectedFleetSettings checks independently installed admission before and
// after reading the exact pinned source. Plain FleetSettingsClient observations
// alone never establish that the writers are administrators.
type ProtectedFleetSettings struct {
	settings   *FleetSettingsClient
	protection *FleetConfigurationProtection
}

var _ app.AdministrationReader = (*ProtectedFleetSettings)(nil)

func NewProtectedFleetSettings(c *PermissionClient, p *FleetConfigurationProtection, name, uid, installation string) (*ProtectedFleetSettings, error) {
	if c == nil || p == nil || p.configMapProtection == nil || p.observer != c || p.plan.SourceName != name {
		return nil, value.ErrInvalid
	}
	s, err := NewFleetSettingsClient(c, name, uid, installation)
	if err != nil {
		return nil, err
	}
	return &ProtectedFleetSettings{s, p}, nil
}

func (s *ProtectedFleetSettings) FleetAdministration(ctx context.Context) (value.Administration, error) {
	var zero value.Administration
	if s == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.settings.client.now()
	_, until, err := s.protection.current(ctx)
	if err != nil {
		return zero, err
	}
	first, err := s.settings.FleetAdministration(ctx)
	if err != nil {
		return zero, err
	}
	last, err := s.settings.FleetAdministration(ctx)
	if err != nil || first.Revision != last.Revision || first.InstallationID != last.InstallationID || first.IssuerEpoch != last.IssuerEpoch {
		return zero, value.ErrUnavailable
	}
	g := s.protection.configMapProtection
	if _, err = checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding); err != nil {
		return zero, err
	}
	first.ObservedAt = start
	first.FreshUntil = identity.Earlier(start.Add(5*time.Second), identity.Earlier(until, identity.Earlier(first.FreshUntil, last.FreshUntil)))
	if ctx.Err() != nil || !first.Valid(s.settings.client.now()) {
		return zero, value.ErrUnavailable
	}
	return first, nil
}
