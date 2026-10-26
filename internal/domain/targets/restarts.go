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
}

func (p PodRestarts) Valid() bool {
	switch p.Reason {
	case "", "OOMKilled", "Error", "Completed", "ContainerCannotRun", "DeadlineExceeded", "Other":
	default:
		return false
	}
	return identity.Text(p.Name, 253) && identity.Text(p.UID, 64) && p.Restarts >= 0 && p.Restarts <= 1<<31 && p.ExitCode >= 0 && p.ExitCode <= 255
}

// RestartObservation is one complete regional Pod LIST of a named workload.
// A truncated or incomplete LIST is never returned: the region fails instead,
// and the hub treats that as Unknown (no trigger fires).
type RestartObservation struct {
	ClusterID              string                     `json:"clusterID"`
	Namespace              configuration.NamespaceRef `json:"namespace"`
	Workload               configuration.WorkloadRef  `json:"workload"`
	Pods                   []PodRestarts              `json:"pods"`
	ObservedAt, FreshUntil time.Time
}

func (o RestartObservation) Valid(now time.Time) bool {
	if !authorization.UUID(o.ClusterID) || !identity.Text(o.Namespace.Name, 63) || !identity.Text(o.Namespace.UID, 64) || (o.Workload.Kind != "Deployment" && o.Workload.Kind != "StatefulSet") || !identity.Text(o.Workload.Name, 253) || !identity.Text(o.Workload.UID, 64) || len(o.Pods) > MaxRestartPods || !identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range o.Pods {
		if !p.Valid() || seen[p.UID] {
			return false
		}
		seen[p.UID] = true
	}
	return true
}
