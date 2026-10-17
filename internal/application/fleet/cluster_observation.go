package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ClusterObservationCallerReader is the purpose-fixed local online TokenReview
// and live workload/guard boundary. The installed loader supplies its concrete
// Kubernetes implementation, never a caller-selected callback or decoded proof.
type ClusterObservationCallerReader interface {
	ObserveClusterObservationCaller(context.Context, []byte, string, value.ClusterObservationRequest) (value.ClusterObservationCaller, error)
}

// ClusterObservationExchange is supplied by the admitted current regional
// channel. Implementations keep the original request/caller deadline and check
// the actual peer before and after the exact local observation. This port does
// not authorize peer bootstrap, source acceptance or any capacity effect.
type ClusterObservationExchange interface {
	ObserveCluster(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error)
}

// The installed HWORK loader supplies its one fixed kubelet-projected token
// file. A request supplies neither a filename nor another account's token.
type ClusterObservationTokenReader interface {
	ReadClusterObservationToken(context.Context) ([]byte, error)
}
