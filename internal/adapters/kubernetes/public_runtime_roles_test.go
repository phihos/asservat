package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	fleet "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
)

type publicRoleRootFixture struct {
	input                 contracts.PublicRuntimeRoles
	root                  *PublicRuntimeRoleRoot
	mu                    sync.Mutex
	object                *core.Secret
	projection            *core.Secret
	federation            *core.Secret
	publisher             *core.Secret
	projectionWrites      atomic.Int32
	lostProjection        atomic.Bool
	lostProjectionClaim   atomic.Bool
	writes                atomic.Int32
	lostCreate, lostClaim bool
	badAdmin              atomic.Bool
	badSecretVersion      atomic.Bool
	configuration         fleet.OwnerConfiguration
	replicas              atomic.Int32
	requests              atomic.Int64
	workerObjects         map[string]any
}

func (f *publicRoleRootFixture) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	if ctx.Err() != nil {
		return fleet.OwnerConfigurationObservation{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return fleet.OwnerConfigurationObservation{Configuration: f.configuration.Clone(), ObservedAt: n, FreshUntil: until}, nil
}
