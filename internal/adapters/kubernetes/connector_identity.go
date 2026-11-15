package kubernetes

import (
	"encoding/hex"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// RegionalSource is the fixed source name of the connector identity document;
// it is part of the deterministic protection digest.
const RegionalSource = "connector-identity"

// ConnectorSourceDigest is the deterministic source protection digest of the
// Helm-native installation (field map, persisted couplings 1): it names the
// cluster, namespace and source, not an admission policy.
func ConnectorSourceDigest(clusterID, namespace, name string) artifact.Digest {
	return contracts.ConfigMapSourceDigest(clusterID, namespace, name)
}

// ConnectorWorkloadDigest is the deterministic workload protection digest of
// one Helm-rendered Deployment (field map, persisted couplings 2).
func ConnectorWorkloadDigest(clusterID, namespace, deployment string) artifact.Digest {
	return contracts.WorkloadSourceDigest(clusterID, namespace, deployment)
}

// ConnectorCatalogPeer is the hub's catalog pin of one regional connector:
// the peer ID as its stable source UID and the deterministic source digest.
func ConnectorCatalogPeer(clusterID, peerID string, d contracts.ConnectorDeployment) (contracts.FederationPeer, error) {
	if !authorization.UUID(clusterID) || !authorization.UUID(peerID) {
		return contracts.FederationPeer{}, value.ErrInvalid
	}
	digest := ConnectorSourceDigest(clusterID, d.Namespace, RegionalSource)
	return contracts.FederationPeer{SourceUID: peerID, ProtectionDigest: hex.EncodeToString(digest[:])}, nil
}
