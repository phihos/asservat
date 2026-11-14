package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type observationSelectionSource struct {
	read func(context.Context, bool) (value.APIContextOwnerCandidates, error)
}

func (s observationSelectionSource) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.read(ctx, false)
}
func (s observationSelectionSource) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return s.read(ctx, true)
}

func observationSelectionPool() value.OwnerPool {
	const id = "11111111-1111-4111-8111-111111111111"
	return value.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
}
