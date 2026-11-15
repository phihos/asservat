package bootstrap

import (
	"os"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// newPublicFleet composes the protected fleet settings that authorize the
// fleet-operator previews; nil without Public.Fleet.
func newPublicFleet(c contracts.OwnerDeployment, observer, probe *kube.PermissionClient) (*kube.ProtectedFleetSettings, error) {
	if c.Public == nil || c.Public.Fleet == nil {
		return nil, nil
	}
	f := c.Public.Fleet
	if observer == nil {
		return nil, &fixedStepError{"fleet-inputs", mounts.ErrUnavailable}
	}
	admins, pin := capacityWorkerGuard(f.SettingsGuard)
	protection, err := kube.NewFleetConfigurationProtection(observer, probe, cfg.ConfigMapAdministration{Name: f.SettingsGuard.Name, SourceName: f.Settings.Name, ControlNamespace: cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, Administrators: admins}, pin)
	if err != nil {
		return nil, &fixedStepError{"fleet-protection", mounts.ErrUnavailable}
	}
	settings, err := kube.NewProtectedFleetSettings(observer, protection, f.Settings.Name, f.Settings.UID, c.InstallationID, c.Public.WorkerPKI.IssuerEpoch)
	if err != nil {
		return nil, &fixedStepError{"fleet-settings", mounts.ErrUnavailable}
	}
	settings.Report = eventLog(os.Stderr, "fleet settings refused")
	return settings, nil
}
