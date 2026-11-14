package bootstrap

import (
	"context"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// newPublicFleet composes the shared bootstrap issuance dependencies and the
// protected fleet settings; nil without Public.Fleet. It needs the installed
// provider layout: the KV channel is the owner's pinned bootstrap-channel
// lifetime. The local and remote cluster bootstraps add their own fixed
// reservations; the settings also authorize the fleet-operator previews.
func newPublicFleet(ctx context.Context, c contracts.OwnerDeployment, providers *kms.InstalledOwnerProviderEffects, pools *publicPools, observer, probe *kube.PermissionClient, a publicAuditStore) (*fleetapp.FleetBootstrapIssuance, error) {
	if c.Public == nil || c.Public.Fleet == nil {
		return nil, nil
	}
	f := c.Public.Fleet
	if providers == nil || providers.BootstrapChannel() == nil || pools == nil || observer == nil || !a.storageConfigured() || a.seal == nil || a.open == nil {
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
	var issues [3]*postgres.BootstrapIssues
	for i, duty := range []string{"record", "audit", "activate"} {
		pool, err := pools.open(ctx, "fleet-bootstrap-"+duty)
		if err != nil {
			return nil, &fixedStepError{"fleet-issue-pool", mounts.ErrUnavailable}
		}
		if issues[i], err = postgres.NewBootstrapIssues(ctx, pool, c.InstallationID); err != nil {
			return nil, &fixedStepError{"fleet-issues", mounts.ErrUnavailable}
		}
	}
	return &fleetapp.FleetBootstrapIssuance{Settings: settings, Credentials: providers.BootstrapChannel(), Records: issues[0], Audits: issues[1],
		Objects: a.bootstrapObjects(), Activation: issues[2], Now: time.Now}, nil
}
