package contracts

// RegionalJoin is the region's public record for the hub's join command
// (ADR-196 decision 2): the bootstrap slot, the connector source the hub
// staged at generation 1 and the executor pin. It holds no credential. The
// operator copies it to the hub, as the offer travels the other way.
const RegionalJoinFormat = "asservat-regional-join/v1"
const RegionalJoinName = "regional-join"
const RegionalJoinFile = "regional-join.json"

// InstallerEvidenceStore is the hub's evidence bucket regional executors
// write to (ADR-196 decision 7); the store ID comes from the capacity
// qualification. RootsPEM are the endpoint's TLS roots.
type InstallerEvidenceStore struct {
	Endpoint string `json:"endpoint"`
	RootsPEM string `json:"rootsPEM"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
}
