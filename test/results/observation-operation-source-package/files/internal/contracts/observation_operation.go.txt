package contracts

// ADR150 selects these literals through original installed input. Decoding an
// envelope cannot select the private operation, alter v1 semantics or negotiate
// another proof profile. The metadata request/result bytes remain unchanged.
const (
	OwnerObservationOperationFormat     = "owner-observation/v2"
	ConnectorObservationOperationFormat = "connector-observation/v2"
	ObservationOperationBytes           = 8 << 10
)

type ObservationOperationRequest struct {
	Format      string `json:"format"`
	RootID      string `json:"rootID"`
	ID          string `json:"id"`
	Challenge   string `json:"challenge"`
	RequestedAt string `json:"requestedAt"`
	NotAfter    string `json:"notAfter"`
}

// Public correlations distinguish the original native bracket from each real
// source-value read. Roles, issuer roots and template pins are independently
// installed and are never chosen by these fields. Final is required at ordinal
// four only; no returned ID or final flag creates private native authority.
type ConnectorObservationOperationReply struct {
	Format             string                      `json:"format"`
	Request            ObservationOperationRequest `json:"request"`
	Ordinal            int                         `json:"ordinal"`
	BracketID          string                      `json:"bracketID"`
	ConnectionBinding  string                      `json:"connectionBinding"`
	ConnectorLeaf      string                      `json:"connectorLeaf"`
	PinDigest          string                      `json:"pinDigest"`
	PodUID             string                      `json:"podUID"`
	ProcessEpoch       string                      `json:"processEpoch"`
	Pod                string                      `json:"pod"`
	ReplicaSetUID      string                      `json:"replicaSetUID"`
	Configuration      APIContextRevision          `json:"configuration"`
	BackingRevision    int64                       `json:"backingRevision"`
	BackingDigest      string                      `json:"backingDigest"`
	SourceDigest       string                      `json:"sourceDigest"`
	NativeStartedAt    string                      `json:"nativeStartedAt"`
	NativeUntil        string                      `json:"nativeUntil"`
	ValueObservedAt    string                      `json:"valueObservedAt"`
	SourceFreshUntil   string                      `json:"sourceFreshUntil"`
	WorkloadDigest     string                      `json:"workloadDigest"`
	WorkloadFreshUntil string                      `json:"workloadFreshUntil"`
	Final              bool                        `json:"final"`
}

func EncodeObservationOperationRequest(v ObservationOperationRequest) ([]byte, error) {
	return encodeObservationRouting(v, ObservationOperationBytes)
}
func DecodeObservationOperationRequest(b []byte) (ObservationOperationRequest, error) {
	return decodeObservationRouting[ObservationOperationRequest](b, ObservationOperationBytes)
}

// Generations/backing revisions are exact integers, like locator sequences.
// Reuse the existing closed raw-integer codec; default RFC8785 conversion would
// round an original value above 2^53. Legacy v1 bytes/codecs remain unchanged.
func EncodeConnectorObservationOperationReply(v ConnectorObservationOperationReply) ([]byte, error) {
	return encodeObservationRouting(v, ObservationOperationBytes)
}
func DecodeConnectorObservationOperationReply(b []byte) (ConnectorObservationOperationReply, error) {
	return decodeObservationRouting[ConnectorObservationOperationReply](b, ObservationOperationBytes)
}
