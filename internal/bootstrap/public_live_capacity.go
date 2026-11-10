package bootstrap

import (
	"slices"

	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/transport/presentation"
)

// composePublicLiveCapacity composes the fleet operators' browser-only,
// single-cluster live-runtime read. The private regional query supplies no
// public authority by itself; current identity, fleet settings and recovery
// remain mandatory for every call.
func composePublicLiveCapacity(c PublicContextOperationsConfig, s PublicContextOperationServices, pc *publicContext) (*presentation.LiveCapacityOperations, error) {
	if pc == nil || pc.fleet == nil {
		return nil, nil
	}
	v, err := composePublicContextUseCases(c, s)
	if err != nil || pc.fleet.Settings == nil || len(pc.clusterIDs) == 0 {
		return nil, presentation.ErrOperationsConfiguration
	}
	targets, ok := pc.investigation.Targets.(liveapp.CapacityTargets)
	if !ok {
		return nil, presentation.ErrOperationsConfiguration
	}
	service := liveapp.CapacityReader{InstallationID: c.InstallationID, Administration: pc.fleet.Settings, Recovery: v.submission.Recovery, Targets: targets, Clusters: slices.Clone(pc.clusterIDs), Now: c.Now}
	return presentation.NewLiveCapacityOperations(c.PublicOrigin, c.Now, c.NewID, service)
}
