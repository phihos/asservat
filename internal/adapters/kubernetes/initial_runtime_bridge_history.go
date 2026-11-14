package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
)

// InitialRuntimeBridgeHistory recognizes only the positively acknowledged final
// bridge. Its constructor holds no SQL administrator/effect facet. It permits
// the existing SELECT-only initial history reader to remain diagnostic during
// later recovery/suspension; it cannot complete a pending bridge or revive any
// installation credential. The original no-bridge history path is unchanged.
type InitialRuntimeBridgeHistory struct{ bridge *InitialRuntimeBridge }

func (h *InitialRuntimeBridgeHistory) Scope() (fleet.InstallationWitnessScope, artifact.Digest) {
	if h == nil || h.bridge == nil {
		return fleet.InstallationWitnessScope{}, artifact.Digest{}
	}
	return h.bridge.record.Scope, h.bridge.record.Claim.PlanDigest
}
func (b *InitialRuntimeBridge) sourceUID(name string) string {
	if name == b.source.input.FleetSource.Name {
		return b.source.input.FleetSource.UID
	}
	if name == b.source.input.OwnerSource.Name {
		return b.source.input.OwnerSource.UID
	}
	return ""
}
