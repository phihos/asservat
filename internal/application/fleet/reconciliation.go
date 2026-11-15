package fleet

import "sync/atomic"

// ConfigurationReconciler runs the serial owner configuration observation
// loop. A leader lease schedules this work; only the observer and its SQL
// transactions can accept state.
type ConfigurationReconciler struct {
	Owner   *OwnerConfigurationObserver
	running atomic.Bool
}
