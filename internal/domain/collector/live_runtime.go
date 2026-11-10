package collector

import (
	"math"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type LiveRuntimeRequest struct {
	ClusterID string `json:"clusterID"`
}

func (r LiveRuntimeRequest) Valid() bool { return authorization.UUID(r.ClusterID) }

// LiveActivity contains only bounded, content-free runtime counts.
type LiveActivity struct {
	Cohorts           int   `json:"cohorts"`
	ScanEvents        int64 `json:"scanEvents"`
	ScanBytes         int64 `json:"scanBytes"`
	ScanCPUNanos      int64 `json:"scanCPUNanos"`
	DeliveredRows     int64 `json:"deliveredRows"`
	DeliveredBytes    int64 `json:"deliveredBytes"`
	RefusedAdmissions int64 `json:"refusedAdmissions"`
}

func (a LiveActivity) Valid() bool {
	return a.Cohorts >= 0 && a.ScanEvents >= 0 && a.ScanBytes >= 0 && a.ScanCPUNanos >= 0 && a.DeliveredRows >= 0 && a.DeliveredBytes >= 0 && a.RefusedAdmissions >= 0
}

func (s LiveStatus) Activity() LiveActivity {
	return LiveActivity{Cohorts: s.Cohorts, ScanEvents: s.ScanEvents, ScanBytes: s.ScanBytes, ScanCPUNanos: s.ScanCPUNanos, DeliveredRows: s.DeliveredRows, DeliveredBytes: s.DeliveredBytes, RefusedAdmissions: s.RefusedAdmissions}
}

// LiveActivityRates is per-second activity across current collector processes.
type LiveActivityRates struct {
	ScanEventsPerSecond        float64 `json:"scanEventsPerSecond"`
	ScanBytesPerSecond         float64 `json:"scanBytesPerSecond"`
	ScanCPUNanosPerSecond      float64 `json:"scanCPUNanosPerSecond"`
	DeliveredRowsPerSecond     float64 `json:"deliveredRowsPerSecond"`
	DeliveredBytesPerSecond    float64 `json:"deliveredBytesPerSecond"`
	RefusedAdmissionsPerSecond float64 `json:"refusedAdmissionsPerSecond"`
}

func (r LiveActivityRates) Valid() bool {
	for _, value := range []float64{r.ScanEventsPerSecond, r.ScanBytesPerSecond, r.ScanCPUNanosPerSecond, r.DeliveredRowsPerSecond, r.DeliveredBytesPerSecond, r.RefusedAdmissionsPerSecond} {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return false
		}
	}
	return true
}

func (r LiveActivityRates) Zero() bool {
	return r.ScanEventsPerSecond == 0 && r.ScanBytesPerSecond == 0 && r.ScanCPUNanosPerSecond == 0 && r.DeliveredRowsPerSecond == 0 && r.DeliveredBytesPerSecond == 0 && r.RefusedAdmissionsPerSecond == 0
}

// LiveRuntimeSnapshot is one region's aggregate at read time. Incomplete rates
// are zero rather than a partial value presented as installation-wide.
type LiveRuntimeSnapshot struct {
	ClusterID        string            `json:"clusterID"`
	ObservedAt       time.Time         `json:"observedAt"`
	FreshUntil       time.Time         `json:"freshUntil"`
	Nodes            int               `json:"nodes"`
	RatesUnavailable int               `json:"ratesUnavailable"`
	RatesComplete    bool              `json:"ratesComplete"`
	Live             *LiveActivity     `json:"live,omitempty"`
	Rates            LiveActivityRates `json:"rates"`
}

func (s LiveRuntimeSnapshot) Valid(now time.Time) bool {
	if !authorization.UUID(s.ClusterID) || !identity.Check(s.ObservedAt, identity.Recheck).Narrow(s.FreshUntil).Valid(now) || s.Nodes < 0 || s.Nodes > 5000 || s.RatesUnavailable < 0 || s.RatesUnavailable > s.Nodes || !s.Rates.Valid() {
		return false
	}
	if s.Live == nil {
		return s.Nodes == 0 && s.RatesUnavailable == 0 && s.RatesComplete && s.Rates.Zero()
	}
	if s.Nodes < 1 || !s.Live.Valid() || s.Live.Cohorts > 16*s.Nodes {
		return false
	}
	return s.RatesComplete == (s.RatesUnavailable == 0) && (s.RatesComplete || s.Rates.Zero())
}
