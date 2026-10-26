package targets

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// MaxRestartPods bounds one restart observation so that its answer, with
// Pod names, fits one 32 KiB query answer frame. A larger workload is not
// observed (Unknown); workload resolution keeps its own 256-Pod bound.
const MaxRestartPods = 128

// PodRestarts is one Pod's whole-pod restart counter and its latest container
// termination (ADR-228). It names no container: the counter sums every
// container of the Pod. Reason and ExitCode come from the most recent
// terminated state; Waiting is the current CrashLoopBackOff wait, if any.
type PodRestarts struct {
	Name     string `json:"name"`
	UID      string `json:"uid"`
	Restarts int64  `json:"restarts"`
	Reason   string `json:"reason,omitempty"`
	ExitCode int32  `json:"exitCode,omitempty"`
	Waiting  bool   `json:"crashLoopBackOff,omitempty"`
	// ProbeFailures and ProbeLast are reported only for a probe observation
	// (ADR-230): a proven lower bound of the Pod's failures of the requested
	// probe type within the window, and the newest such failure (unix
	// seconds), both from Kubernetes Events. No Event text is reported.
	ProbeFailures int64 `json:"probeFailures,omitempty"`
	ProbeLast     int64 `json:"probeLast,omitempty"`
}

// MinProbeLast is the smallest accepted failure second (2001-09-09), so a
// probe failure time can never equal a restart count (ADR-230).
const MinProbeLast = 1000000000

// Probe observation windows (ADR-230): at least two polls, at most the
// five-minute correlation ceiling (REQ-TRG-002).
const (
	MinProbeWindowSeconds = 30
	MaxProbeWindowSeconds = 300
)

// ProbeType reports whether t names a Kubernetes probe type.
func ProbeType(t string) bool {
	return t == "Liveness" || t == "Readiness" || t == "Startup"
}

// RestartRequest names the workload to observe and, for a probe detector
// (ADR-230), the probe type and window whose Event failures the region adds.
type RestartRequest struct {
	WorkloadRequest
	Probe              string `json:",omitempty"`
	ProbeWindowSeconds int64  `json:",omitempty"`
}

func (r RestartRequest) Valid() bool {
	if !r.WorkloadRequest.Valid() || r.Kind == "Pod" {
		return false
	}
	if r.Probe == "" {
		return r.ProbeWindowSeconds == 0
	}
	return ProbeType(r.Probe) && r.ProbeWindowSeconds >= MinProbeWindowSeconds && r.ProbeWindowSeconds <= MaxProbeWindowSeconds
}

func (p PodRestarts) Valid() bool {
	switch p.Reason {
	case "", "OOMKilled", "Error", "Completed", "ContainerCannotRun", "DeadlineExceeded", "Other":
	default:
		return false
	}
	return identity.Text(p.Name, 253) && identity.Text(p.UID, 64) && p.Restarts >= 0 && p.Restarts <= 1<<31 && p.ExitCode >= 0 && p.ExitCode <= 255 &&
		p.ProbeFailures >= 0 && p.ProbeFailures <= 1<<31 && (p.ProbeLast == 0 || p.ProbeLast >= MinProbeLast && p.ProbeLast < 1<<31) && (p.ProbeFailures == 0 || p.ProbeLast != 0)
}

// RestartObservation is one complete regional Pod LIST of a named workload.
// A truncated or incomplete LIST is never returned: the region fails instead,
// and the hub treats that as Unknown (no trigger fires).
type RestartObservation struct {
	ClusterID string                     `json:"clusterID"`
	Namespace configuration.NamespaceRef `json:"namespace"`
	Workload  configuration.WorkloadRef  `json:"workload"`
	Pods      []PodRestarts              `json:"pods"`
	// Probe echoes the probe type of a probe observation (ADR-230).
	Probe                  string `json:"probe,omitempty"`
	ObservedAt, FreshUntil time.Time
}

func (o RestartObservation) Valid(now time.Time) bool {
	if !authorization.UUID(o.ClusterID) || !identity.Text(o.Namespace.Name, 63) || !identity.Text(o.Namespace.UID, 64) || (o.Workload.Kind != "Deployment" && o.Workload.Kind != "StatefulSet") || !identity.Text(o.Workload.Name, 253) || !identity.Text(o.Workload.UID, 64) || len(o.Pods) > MaxRestartPods || !identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) {
		return false
	}
	if o.Probe != "" && !ProbeType(o.Probe) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range o.Pods {
		if !p.Valid() || seen[p.UID] || o.Probe == "" && (p.ProbeFailures != 0 || p.ProbeLast != 0) {
			return false
		}
		seen[p.UID] = true
	}
	return true
}
