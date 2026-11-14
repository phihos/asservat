package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
)

// HubDeploymentNames returns the hub-api and hub-worker Deployment names.
func HubDeploymentNames(installation string) (hubAPI, hubWorker string) {
	n := runtimeResourceNames(installation)
	return n.Owner, n.Worker
}

// HubDeploymentNamesList is HubDeploymentNames as a list.
func HubDeploymentNamesList(installation string) []string {
	a, w := HubDeploymentNames(installation)
	return []string{a, w}
}

// ReleaseFollowerNames are the hub-namespace Deployments that follow the
// release image without any runtime check of their own image (ADR-227 phase
// 3): the key service, publisher and federation, in rollout order. Each exists
// only when the installation enabled it.
func ReleaseFollowerNames(installation string) []string {
	return []string{contracts.KeyServiceName(installation), contracts.PublisherName(installation), FederationWorkloadName(installation)}
}

// HubDeploymentSettled reports whether the Deployment's controller has
// observed its current generation and runs exactly one updated, available
// replica with no other ReplicaSet holding replicas.
func HubDeploymentSettled(d apps.Deployment) bool {
	s := d.Status
	return d.Spec.Replicas != nil && *d.Spec.Replicas == 1 && s.ObservedGeneration == d.Generation && s.Replicas == 1 && s.UpdatedReplicas == 1 && s.AvailableReplicas == 1 && s.ReadyReplicas == 1 && s.UnavailableReplicas == 0
}
