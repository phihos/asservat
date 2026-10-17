package contracts

import "bytes"

const (
	ConnectorObservationFormat = "connector-observation/v1"
	ConnectorObservationBytes  = 8 << 10
	ConnectorObservationChecks = 4
)

// This fixed reply contains only public own-process facts. Full issuer roots,
// role names and immutable workload pins come from independently installed
// input; a received observation cannot change them. No token/hash/CSR is sent.
type ConnectorObservationReply struct {
	Format             string                  `json:"format"`
	Request            OwnerObservationRequest `json:"request"`
	Ordinal            int                     `json:"ordinal"`
	ConnectionBinding  string                  `json:"connectionBinding"`
	ConnectorLeaf      string                  `json:"connectorLeaf"`
	PinDigest          string                  `json:"pinDigest"`
	PodUID             string                  `json:"podUID"`
	ProcessEpoch       string                  `json:"processEpoch"`
	Pod                string                  `json:"pod"`
	ReplicaSetUID      string                  `json:"replicaSetUID"`
	Configuration      APIContextRevision      `json:"configuration"`
	BackingRevision    int64                   `json:"backingRevision"`
	BackingDigest      string                  `json:"backingDigest"`
	SourceDigest       string                  `json:"sourceDigest"`
	SourceObservedAt   string                  `json:"sourceObservedAt"`
	SourceFreshUntil   string                  `json:"sourceFreshUntil"`
	WorkloadDigest     string                  `json:"workloadDigest"`
	WorkloadObservedAt string                  `json:"workloadObservedAt"`
	WorkloadFreshUntil string                  `json:"workloadFreshUntil"`
	ObservedAt         string                  `json:"observedAt"`
	FreshUntil         string                  `json:"freshUntil"`
}

func EncodeConnectorObservationReply(v ConnectorObservationReply) ([]byte, error) {
	return canonicalAPIContext(v, ConnectorObservationBytes)
}
func DecodeConnectorObservationReply(b []byte) (ConnectorObservationReply, error) {
	return decodeClosedRPC[ConnectorObservationReply](bytes.NewReader(b), ConnectorObservationBytes)
}
