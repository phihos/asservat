package kubernetes

import (
	"context"
	"sync/atomic"

	fleet "asservat.local/asservat/internal/domain/fleet"
)

// The API enforcement, original activation and accepted SQL source in this
// loopback fixture are explicitly synthetic. Actual production constructors,
// complete negative proof calls, original clock and CAS bodies remain intact.
// This exercises composition; it is neither native Kubernetes admission nor a
// real SQL/provider qualification or a measurement of API-rate availability.
type ownerIdentityProducerFixture struct {
	api       *preparerFixture
	resources *InitialRuntimeResources
	bridge    *InitialRuntimeBridge
	root      *OwnerIdentityRoleRoot
	source    *ConfigurationRoleSource
	accepted  *ownerIdentityAcceptedFixture
	effects   *rootPinEffectFixture
	fault     atomic.Int32
}

type ownerIdentityAcceptedFixture struct {
	source *OwnerConfigurationSource
	fault  *atomic.Int32
}

func (s *ownerIdentityAcceptedFixture) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	v, e := s.source.ReadOwnerConfiguration(ctx)
	if e == nil && s.fault.Load() == 3 {
		v.Configuration.Pool.ServiceUID = ownerID(4900)
	}
	return v, e
}
