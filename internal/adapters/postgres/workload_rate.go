package postgres

import (
	"sync/atomic"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
)

// workloadRate is the installation's capacity.workload.dump value, which
// the hub-api sets once at startup (SetWorkloadRate).
var workloadRate atomic.Pointer[value.WorkloadRate]

func currentWorkloadRate() value.WorkloadRate {
	if r := workloadRate.Load(); r != nil {
		return *r
	}
	return value.DefaultWorkloadRate()
}

// SetWorkloadRate sets the workload token bucket; zero keeps a default.
func SetWorkloadRate(burst, intervalSeconds int64) {
	r := currentWorkloadRate()
	if burst > 0 {
		r.Burst = int(burst)
	}
	if intervalSeconds > 0 {
		r.Interval = time.Duration(intervalSeconds) * time.Second
	}
	workloadRate.Store(&r)
}
