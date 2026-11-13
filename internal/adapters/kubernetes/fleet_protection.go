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

// ProtectedFleetSettings reads the exact named fleet source once under
// ordinary RBAC within its original five-second window.
type ProtectedFleetSettings struct {
	settings   *FleetSettingsClient
	protection *FleetConfigurationProtection
	Report     func(string)
}

func (s *ProtectedFleetSettings) note(stage string) {
	if s.Report != nil {
		s.Report(stage)
	}
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
	return &ProtectedFleetSettings{settings: s, protection: p}, nil
}

func (s *ProtectedFleetSettings) FleetAdministration(ctx context.Context) (value.Administration, error) {
	var zero value.Administration
	if s == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	start := s.settings.client.now()
	first, err := s.settings.FleetAdministration(ctx)
	if err != nil {
		s.note("first-source")
		return zero, err
	}
	first.ObservedAt = start
	first.FreshUntil = identity.Earlier(start.Add(5*time.Second), first.FreshUntil)
	if ctx.Err() != nil || !first.Valid(s.settings.client.now()) {
		s.note("valid")
		return zero, value.ErrUnavailable
	}
	return first, nil
}
