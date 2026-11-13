package bootstrap

import (
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// validateHubWorkerInputs checks the old installer's hub-worker input. Only
// the installer still produces it; slice 4 of the Helm-native installation
// deletes it with the installer.
func validateHubWorkerInputs(c contracts.HubWorkerDeployment) error {
	if c.Activation != nil && !kube.HubWorkerActivationBound(c) {
		return mounts.ErrUnavailable
	}
	if c.Format != contracts.HubWorkerDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.ClusterID) || !authorization.UUID(c.Namespace.UID) || len(validation.IsDNS1123Label(c.Namespace.Name)) != 0 {
		return mounts.ErrUnavailable
	}
	for _, r := range []contracts.WorkerObjectReference{c.FleetSource, c.OwnerSource, c.LeaderLease} {
		if !authorization.UUID(r.UID) || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
			return mounts.ErrUnavailable
		}
	}
	if c.FleetSource == c.OwnerSource || c.FleetSource.Name == c.OwnerSource.Name || c.FleetGuard.Name == c.OwnerGuard.Name {
		return mounts.ErrUnavailable
	}
	for _, g := range []contracts.OwnerDeploymentGuard{c.FleetGuard, c.OwnerGuard} {
		if !identity.Text(g.Name, 253) || !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || !identity.Text(g.BindingResourceVersion, 128) || g.PolicyGeneration < 1 || g.PolicyGeneration >= 1<<53 || len(g.Administrators) < 1 || len(g.Administrators) > 32 {
			return mounts.ErrUnavailable
		}
		seen := map[contracts.OwnerDeploymentActor]bool{}
		for _, a := range g.Administrators {
			if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) || seen[a] {
				return mounts.ErrUnavailable
			}
			seen[a] = true
		}
	}
	if providerconfig.Validate(c.Kubernetes, c.Postgres, c.AuditStore, c.KeyService, time.Now()) != nil {
		return mounts.ErrUnavailable
	}
	return nil
}

// capacityWorkerGuard converts an installer guard pin; the hub-api's
// installer-produced inputs still carry them until slice 4.
func capacityWorkerGuard(g contracts.OwnerDeploymentGuard) ([]cfg.KubernetesActor, kube.GuardPin) {
	a := make([]cfg.KubernetesActor, len(g.Administrators))
	for i, v := range g.Administrators {
		a[i] = cfg.KubernetesActor{Kind: v.Kind, Name: v.Name}
	}
	return a, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
