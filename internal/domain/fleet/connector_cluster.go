package fleet

import "asservat.local/asservat/internal/domain/authorization"

// ConnectorCluster is the registered workload cluster a connector's
// ServiceAccount token was attributed to (ADR-334): the hub's values name
// the cluster, the hub derives its connector peer.
type ConnectorCluster struct {
	RootID, PeerID, InstallationID, ClusterID string
}

func (p ConnectorCluster) Valid() bool {
	return authorization.UUID(p.RootID) && authorization.UUID(p.PeerID) && authorization.UUID(p.InstallationID) && authorization.UUID(p.ClusterID)
}
