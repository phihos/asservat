package contracts

import "bytes"

const ClusterObservationLocalPath = "/internal/cluster-observation/v1"
const ClusterObservationLocalMedia = "application/vnd.asservat.cluster-observation+json"
const ClusterObservationLocalFormat = "local-cluster-observation/v1"

// PodUID is an untrusted matching hint for the online local TokenReview. It is
// never copied into an authenticated caller without the exact live chain.
type ClusterObservationLocalRequest struct {
	Format      string                    `json:"format"`
	PodUID      string                    `json:"podUID"`
	Observation ClusterObservationRequest `json:"observation"`
}

func EncodeClusterObservationLocalRequest(v ClusterObservationLocalRequest) ([]byte, error) {
	b, e := canonicalAPIContext(v, ClusterObservationBytes)
	if e != nil {
		return nil, ErrClusterObservationProtocol
	}
	return b, nil
}
func DecodeClusterObservationLocalRequest(b []byte) (ClusterObservationLocalRequest, error) {
	v, e := decodeClosedRPC[ClusterObservationLocalRequest](bytes.NewReader(b), ClusterObservationBytes)
	if e != nil {
		return ClusterObservationLocalRequest{}, ErrClusterObservationProtocol
	}
	return v, nil
}
