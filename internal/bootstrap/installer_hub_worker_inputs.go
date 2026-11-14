package bootstrap

import (
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

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
