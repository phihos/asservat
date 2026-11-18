package bootstrap

import (
	"k8s.io/apimachinery/pkg/util/validation"

	"asservat.local/asservat/internal/contracts"
)

// hubAPIRemoteCluster is one registered mode=cluster workload cluster
// (values clusters[]) with its derived cluster ID and connector peer.
type hubAPIRemoteCluster struct {
	contracts.RemoteCluster
	clusterID, peerID string
}

// hubAPIRemoteClusters checks the registered clusters: distinct DNS-label
// names, a release namespace and the router's per-cluster reservations.
// Cluster IDs derive from the names (ADR-335 D4).
func hubAPIRemoteClusters(h contracts.HubAPIConfig, ids hubAPIIDs) ([]hubAPIRemoteCluster, error) {
	if len(h.Clusters) == 0 {
		return nil, nil
	}
	if h.Public == nil || h.Public.RegionalOffer == nil {
		return nil, hubAPIInputError("clusters")
	}
	seen := map[string]bool{ids.ClusterID: true}
	out := make([]hubAPIRemoteCluster, 0, len(h.Clusters))
	for _, c := range h.Clusters {
		cluster := contracts.RemoteClusterID(ids.InstallationID, c.Name)
		peer, ok := contracts.RemotePeerID(ids.InstallationID, cluster)
		if !ok || seen[cluster] || len(validation.IsDNS1123Label(c.Name)) != 0 || len(validation.IsDNS1123Label(c.Namespace)) != 0 || c.Captures < 1 {
			return nil, hubAPIInputError("clusters")
		}
		seen[cluster] = true
		out = append(out, hubAPIRemoteCluster{RemoteCluster: c, clusterID: cluster, peerID: peer})
	}
	return out, nil
}
