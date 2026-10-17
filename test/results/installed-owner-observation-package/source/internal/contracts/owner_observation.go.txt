package contracts

import "bytes"

const (
	OwnerObservationFormat = "owner-observation/v1"
	OwnerObservationPath   = "/internal/cluster-observation/owner/v1"
	OwnerObservationMedia  = "application/vnd.asservat.owner-observation+json"
	OwnerObservationBytes  = 8 << 10
)

// This purpose returns only the installed server's own public identity facts.
// Workload targets, tokens, source writes and effect commands are not members.
type OwnerObservationRequest struct {
	Format      string `json:"format"`
	RootID      string `json:"rootID"`
	ID          string `json:"id"`
	Challenge   string `json:"challenge"`
	RequestedAt string `json:"requestedAt"`
	NotAfter    string `json:"notAfter"`
}

// Certificates and the original pin are independently known on the receiving
// side; their exact digests bind them without returning issuer roots or specs.
type OwnerObservationReply struct {
	Format             string                  `json:"format"`
	Request            OwnerObservationRequest `json:"request"`
	ConnectionBinding  string                  `json:"connectionBinding"`
	ConnectorLeaf      string                  `json:"connectorLeaf"`
	OwnerLeaf          string                  `json:"ownerLeaf"`
	PinDigest          string                  `json:"pinDigest"`
	EnrollmentID       string                  `json:"enrollmentID"`
	Pod                string                  `json:"pod"`
	ReplicaSetUID      string                  `json:"replicaSetUID"`
	Configuration      APIContextRevision      `json:"configuration"`
	ProtectionDigest   string                  `json:"protectionDigest"`
	WorkloadDigest     string                  `json:"workloadDigest"`
	OwnerObservedAt    string                  `json:"ownerObservedAt"`
	OwnerFreshUntil    string                  `json:"ownerFreshUntil"`
	WorkloadObservedAt string                  `json:"workloadObservedAt"`
	WorkloadFreshUntil string                  `json:"workloadFreshUntil"`
	ObservedAt         string                  `json:"observedAt"`
	FreshUntil         string                  `json:"freshUntil"`
}

func EncodeOwnerObservationRequest(v OwnerObservationRequest) ([]byte, error) {
	return canonicalAPIContext(v, OwnerObservationBytes)
}
func DecodeOwnerObservationRequest(b []byte) (OwnerObservationRequest, error) {
	return decodeClosedRPC[OwnerObservationRequest](bytes.NewReader(b), OwnerObservationBytes)
}
func EncodeOwnerObservationReply(v OwnerObservationReply) ([]byte, error) {
	return canonicalAPIContext(v, OwnerObservationBytes)
}
func DecodeOwnerObservationReply(b []byte) (OwnerObservationReply, error) {
	return decodeClosedRPC[OwnerObservationReply](bytes.NewReader(b), OwnerObservationBytes)
}
