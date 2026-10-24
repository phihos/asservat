package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

// RegionalObservationOperationCluster is one joined regional capacity
// cluster's original installed profile and its concrete SQL49 registry.
type RegionalObservationOperationCluster struct {
	Pin      value.ConnectorObservationPin
	Registry *postgres.ConnectorObservationOperationRegistry
}

// NewRegionalObservationOperationHandler composes the joined regional
// profiles with their concrete SQL49 registries and actual receiving
// stream/TLS state. A standby's hello selects its cluster's profile; the
// coordinator still requires the authenticated peer to be that profile's
// exact binding, so one region cannot stand by for another. It does not
// enable a listener or choose a profile from wire. The holder and listener
// retain their independent process/socket ceilings.
func NewRegionalObservationOperationHandler(host string, holder *clusterobservation.HubObservationOperationHolder, clusters []RegionalObservationOperationCluster, ingress *mtls.OwnerObservationOperationIngress, now func() time.Time) (*clusterobservation.HubObservationOperationHandler, error) {
	out := make([]regionalOperationCluster, 0, len(clusters))
	for _, c := range clusters {
		if c.Registry == nil {
			return nil, value.ErrInvalid
		}
		out = append(out, regionalOperationCluster{c.Pin, c.Registry})
	}
	return regionalObservationOperationHandler(host, holder, out, ingress, now)
}

type regionalOperationCluster struct {
	pin      value.ConnectorObservationPin
	registry app.ConnectorObservationOperationRegistry
}

// regionalOperationClusters indexes the profiles by cluster: at least one,
// each valid, under one root, and no cluster twice.
func regionalOperationClusters(clusters []regionalOperationCluster) (map[string]regionalOperationCluster, error) {
	if len(clusters) < 1 || len(clusters) > 16 {
		return nil, value.ErrInvalid
	}
	out := make(map[string]regionalOperationCluster, len(clusters))
	for _, c := range clusters {
		id := c.pin.Profile.Binding.ClusterID
		if !c.pin.Valid() || c.registry == nil || c.pin.Profile.RootID != clusters[0].pin.Profile.RootID {
			return nil, value.ErrInvalid
		}
		if _, dup := out[id]; dup {
			return nil, value.ErrInvalid
		}
		out[id] = regionalOperationCluster{c.pin.Clone(), c.registry}
	}
	return out, nil
}

// The private seam permits deterministic tests of current SQL failure. Only the
// public constructor above is used by installed composition, with the fixed
// concrete registries. No wire/request can supply this dependency.
func regionalObservationOperationHandler(host string, holder *clusterobservation.HubObservationOperationHolder, clusters []regionalOperationCluster, ingress *mtls.OwnerObservationOperationIngress, now func() time.Time) (*clusterobservation.HubObservationOperationHandler, error) {
	byCluster, err := regionalOperationClusters(clusters)
	if err != nil || ingress == nil || now == nil {
		return nil, value.ErrInvalid
	}
	// One closed refusal stage and cause per change, for operator
	// diagnostics (ADR-197); never remote or SQL text.
	var mu sync.Mutex
	last := ""
	refused := func(stage string, err error) {
		line := stage + " (" + regionalCause(err) + ")"
		mu.Lock()
		defer mu.Unlock()
		if line != last {
			last = line
			fmt.Fprintln(os.Stderr, "regional standby refused: "+line)
		}
	}
	return clusterobservation.NewHubObservationOperationHandler(host, holder, func(root, setup context.Context, state *tls.ConnectionState, hello contracts.ClusterObservationHello, stream *clusterobservation.HubObservationOperationStream) (clusterobservation.HubObservationOperationConversation, error) {
		c, known := byCluster[hello.ClusterID]
		if setup == nil || setup.Err() != nil || !known || hello.RootID != c.pin.Profile.RootID {
			refused("hello", value.ErrUnavailable)
			return nil, value.ErrUnavailable
		}
		coordinator, err := mtls.NewHubConnectorObservationOperation(root, c.pin, ingress, c.registry, stream, state, hello, now)
		if err != nil {
			refused("coordinator", err)
			return nil, err
		}
		if setup.Err() != nil {
			coordinator.Close()
			return nil, value.ErrUnavailable
		}
		return &regionalObservationOperationStandby{coordinator: coordinator}, nil
	}, now)
}

// A standby is created before any query. Only the accepted locator record can
// lend its exact private native operation after this original holder sequence
// is spent. This wrapper never opens, rediscovers, renews or closes that proof.
type regionalObservationOperationStandby struct {
	coordinator            *mtls.HubConnectorObservationOperation
	mu                     sync.Mutex
	operation              *mtls.OwnerObservationOperation
	bound, started, closed bool
}

func (s *regionalObservationOperationStandby) bind(operation *mtls.OwnerObservationOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if operation == nil || s.closed || s.bound || s.started {
		return value.ErrUnavailable
	}
	s.bound = true
	s.operation = operation
	return nil
}
func (s *regionalObservationOperationStandby) ObserveCluster(ctx context.Context, request value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	s.mu.Lock()
	if s.closed || !s.bound || s.started || ctx == nil || ctx.Err() != nil {
		s.mu.Unlock()
		return value.ClusterObservationResult{}, value.ErrUnavailable
	}
	s.started = true
	operation := s.operation
	s.mu.Unlock()
	return s.coordinator.ObserveClusterOperation(ctx, request, operation)
}
func (s *regionalObservationOperationStandby) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.coordinator.Close()
}

// ObserveRegionalOperation consumes the already selected original holder once.
// Its caller owns the accepted locator's original finite root and sole proof
// Close. An uncertain result is spent; calling Lookup again is not recovery.
func ObserveRegionalOperation(ctx context.Context, holder *clusterobservation.HubObservationOperationHolder, locator clusterobservation.HubObservationLocator, request value.ClusterObservationRequest, operation *mtls.OwnerObservationOperation) (value.ClusterObservationResult, error) {
	var zero value.ClusterObservationResult
	if holder == nil || operation == nil {
		return zero, value.ErrUnavailable
	}
	claim, err := holder.Claim(ctx, locator, request)
	if err != nil {
		return zero, err
	}
	defer claim.Close()
	standby, ok := claim.Conversation().(*regionalObservationOperationStandby)
	if !ok || standby.bind(operation) != nil {
		return zero, value.ErrUnavailable
	}
	return claim.Observe()
}
