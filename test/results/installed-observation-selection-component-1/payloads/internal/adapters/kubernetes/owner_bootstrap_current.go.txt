package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// One actual named child GET under each already proved initial/post-lock/final
// phase. No extra full bracket or mutable-source caching is hidden here.
func (s *OwnerIdentityProjection) originalBootstrapSelection(ctx context.Context, snapshot contracts.InitialRuntimeResourceSnapshot, until time.Time) error {
	if !ownerBootstrapDeploymentBound(s.input, snapshot.State) {
		return cfg.ErrChanged
	}
	plan := contracts.OwnerBootstrapPlan{ObservationFormat: snapshot.State.ObservationFormat, Format: contracts.OwnerBootstrapPlanFormat, PKIMount: s.input.KeyService.PKIMount, Connections: s.input.Connections, Concurrency: s.input.Concurrency}
	for _, peer := range s.input.Observation.Peers {
		plan.Peers = append(plan.Peers, contracts.OwnerBootstrapPeerPlan{ClusterID: peer.ClusterID, Roots: peer.Roots})
	}
	body, err := ownerBootstrapBody(s.root, snapshot.State.OwnerBootstrap, plan)
	if err != nil || !ownerBootstrapBodyBound(s.root, snapshot.State.OwnerBootstrap, body) {
		return cfg.ErrChanged
	}
	phase := &ownerBootstrapPhase{producer: &OwnerBootstrapSelectionProducer{root: s.root}, snapshot: snapshot, body: body, until: until}
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	_, err = phase.readChild(call)
	return err
}
