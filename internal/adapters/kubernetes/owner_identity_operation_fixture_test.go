package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// The API enforcement, original activation and accepted SQL source in this
// loopback fixture are explicitly synthetic. Actual production constructors,
// complete negative proof calls, original clock and CAS bodies remain intact.
// This exercises composition; it is neither native Kubernetes admission nor a
// real SQL/provider qualification or a measurement of API-rate availability.
type ownerIdentityOperationFixture struct {
	api       *preparerFixture
	resources *InitialRuntimeResources
	bridge    *InitialRuntimeBridge
	root      *OwnerIdentityRoleRoot
	source    *ConfigurationRoleSource
	accepted  *ownerIdentityOperationAcceptedFixture
	effects   *rootPinEffectFixture
	fault     atomic.Int32
}

// The accepted SQL value is a separate stored fixture observation. Reads do
// not call the native source or refresh its timestamps. Tests may explicitly
// install a new value or run a separately recorded finite observer cadence.
type ownerIdentityOperationAcceptedFixture struct {
	mu    sync.Mutex
	value fleet.OwnerConfigurationObservation
	fault *atomic.Int32
}

func (s *ownerIdentityOperationAcceptedFixture) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return fleet.OwnerConfigurationObservation{}, cfg.ErrUnavailable
	}
	v := s.value
	v.Configuration = v.Configuration.Clone()
	if s.fault.Load() == 3 {
		v.Configuration.Pool.ServiceUID = ownerID(4900)
	}
	return v, nil
}

// An explicitly independent, finite synthetic SQL observer schedule for the
// multi-phase functional loop only. It never reacts to operation reads or
// changes configuration identity. Real SQL/native availability is separate.
func startOwnerIdentityOperationAcceptedObserver(t *testing.T, f *ownerIdentityOperationFixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for observation := 0; observation < 15; observation++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC().Truncate(time.Microsecond)
				f.accepted.mu.Lock()
				f.accepted.value.ObservedAt, f.accepted.value.FreshUntil = now, now.Add(5*time.Second)
				f.accepted.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-joined })
}
