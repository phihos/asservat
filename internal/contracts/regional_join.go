package contracts

import "io"

// RegionalJoin is the region's public record for the hub's join command
// (ADR-196 decision 2): the bootstrap slot, the connector source the hub
// staged at generation 1 and the executor pin. It holds no credential. The
// operator copies it to the hub, as the offer travels the other way.
const RegionalJoinFormat = "asservat-regional-join/v1"
const RegionalJoinName = "regional-join"
const RegionalJoinFile = "regional-join.json"
const RegionalJoinMaxBytes = 256 << 10

type RegionalJoin struct {
	Format         string              `json:"format"`
	InstallationID string              `json:"installationID"`
	ClusterID      string              `json:"clusterID"`
	PeerID         string              `json:"peerID"`
	IssuerEpoch    string              `json:"issuerEpoch"`
	Connector      FederationPeer      `json:"connector"`
	Executor       OwnerPublicExecutor `json:"executor"`
	// Capacity is the region's ADR-197 capacity assertion: its selector
	// guard's proven digest and keys, and its Deployment's template and
	// workload guard digests for the hub's connector observation pin.
	Capacity *RegionalJoinCapacity `json:"capacity,omitempty"`
}

type RegionalJoinCapacity struct {
	NamespaceGuardDigest string   `json:"namespaceGuardDigest"`
	Keys                 []string `json:"keys"`
	TemplateDigest       string   `json:"templateDigest"`
	ProtectionDigest     string   `json:"protectionDigest"`
}

func DecodeRegionalJoin(r io.Reader) (RegionalJoin, error) {
	return decodeClosedRPC[RegionalJoin](r, RegionalJoinMaxBytes)
}

// InstallerEvidenceStore is the hub's evidence bucket regional executors
// write to (ADR-196 decision 7); the store ID comes from the capacity
// qualification. RootsPEM are the endpoint's TLS roots.
type InstallerEvidenceStore struct {
	Endpoint string `json:"endpoint"`
	RootsPEM string `json:"rootsPEM"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
}
