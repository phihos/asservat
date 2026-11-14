package fleet

import (
	"errors"

	"asservat.local/asservat/internal/domain/authorization"
)

// ErrNotStaged reports that a registered cluster's connector source was
// never staged; only this case stages it on the first conversation.
var ErrNotStaged = errors.New("connector source not staged")

// ConnectorCluster is the registered workload cluster a connector's
// ServiceAccount token was attributed to (ADR-334): the hub's values name
// the cluster, the hub derives its connector peer.
type ConnectorCluster struct {
	RootID, PeerID, InstallationID, ClusterID string
}

func (p ConnectorCluster) Valid() bool {
	return authorization.UUID(p.RootID) && authorization.UUID(p.PeerID) && authorization.UUID(p.InstallationID) && authorization.UUID(p.ClusterID)
}
