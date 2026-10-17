package contracts

// V2 is selected by original installation input, never negotiated from a frame.
// The existing v1 exchange and metadata request/digest bytes remain unchanged.
const ClusterObservationOperationExchangeFormat = "cluster-observation-exchange/v2"

type OwnerObservationOperationReply struct {
	Format                 string                      `json:"format"`
	Request                ObservationOperationRequest `json:"request"`
	Ordinal                int                         `json:"ordinal"`
	BracketID              string                      `json:"bracketID"`
	ConnectionBinding      string                      `json:"connectionBinding"`
	ConnectorLeaf          string                      `json:"connectorLeaf"`
	OwnerLeaf              string                      `json:"ownerLeaf"`
	PinDigest              string                      `json:"pinDigest"`
	EnrollmentID           string                      `json:"enrollmentID"`
	Pod                    string                      `json:"pod"`
	ReplicaSetUID          string                      `json:"replicaSetUID"`
	Configuration          APIContextRevision          `json:"configuration"`
	WorkloadDigest         string                      `json:"workloadDigest"`
	NativeStartedAt        string                      `json:"nativeStartedAt"`
	NativeUntil            string                      `json:"nativeUntil"`
	RegistrationObservedAt string                      `json:"registrationObservedAt"`
	RegistrationUntil      string                      `json:"registrationUntil"`
	Final                  bool                        `json:"final"`
}
type ClusterObservationOperationProbe struct {
	Format     string                         `json:"format"`
	ExchangeID string                         `json:"exchangeID"`
	Ordinal    int                            `json:"ordinal"`
	Owner      OwnerObservationOperationReply `json:"owner"`
}

func EncodeOwnerObservationOperationReply(v OwnerObservationOperationReply) ([]byte, error) {
	return encodeObservationRouting(v, ObservationOperationBytes)
}
func DecodeOwnerObservationOperationReply(b []byte) (OwnerObservationOperationReply, error) {
	return decodeObservationRouting[OwnerObservationOperationReply](b, ObservationOperationBytes)
}
func EncodeClusterObservationOperationProbe(v ClusterObservationOperationProbe) ([]byte, error) {
	return encodeObservationRouting(v, 2*ObservationOperationBytes)
}
func DecodeClusterObservationOperationProbe(b []byte) (ClusterObservationOperationProbe, error) {
	return decodeObservationRouting[ClusterObservationOperationProbe](b, 2*ObservationOperationBytes)
}
