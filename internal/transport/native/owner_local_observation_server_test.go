package native_test

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

type observationLocalCaller func(context.Context, []byte, string, value.ClusterObservationRequest) (value.ClusterObservationCaller, error)

func (f observationLocalCaller) ObserveClusterObservationCaller(ctx context.Context, token []byte, pod string, r value.ClusterObservationRequest) (value.ClusterObservationCaller, error) {
	return f(ctx, token, pod, r)
}

type observationLocalExchange struct{}

func (observationLocalExchange) ObserveCluster(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	return value.ClusterObservationResult{}, value.ErrDenied
}
