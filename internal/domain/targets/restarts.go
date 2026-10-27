package targets

import (
	"strings"
	"time"
	"unicode/utf8"

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
	// seconds), both from Kubernetes Events. No Event text is reported. For
	// an alert observation (ADR-231) they are the number of matching active
	// Alertmanager alerts naming the Pod and the newest alert's startsAt
	// second; no alert label or annotation is reported.
	ProbeFailures int64 `json:"probeFailures,omitempty"`
	ProbeLast     int64 `json:"probeLast,omitempty"`
	// Unknown marks a Pod of a log or resource observation (ADR-241) whose
	// level could not be established this poll: a failed or truncated log
	// read without a match, or a missing, stale or partial metrics sample.
	// It neither fires, baselines nor re-arms. Overlong marks a log
	// observation whose window held a record longer than maxRecordBytes that
	// was dropped rather than evaluated. Neither carries content.
	Unknown  bool `json:"unknown,omitempty"`
	Overlong bool `json:"overlong,omitempty"`
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

// MaxAlertLabels bounds an alert detector's label matchers (ADR-231), as the
// canonical schema does.
const MaxAlertLabels = 16

// AlertLabelName reports whether n is a Prometheus label name an alert
// detector may match. namespace and pod are excluded: the policy's
// namespace and the observed Pod names already select them.
func AlertLabelName(n string) bool {
	if n == "" || len(n) > 128 || n == "namespace" || n == "pod" {
		return false
	}
	for i, c := range n {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// Log detector bounds (ADR-241): the canonical schema's pattern and record
// limits, at most MaxLogStreams container logs and MaxLogBytes read per
// observation, and at most MaxLogPodBytes per Pod (REQ-TRG-001), split
// evenly across its containers.
const (
	MaxLogPattern     = 1024
	MaxLogJSONField   = 128
	MaxLogJSONDepth   = 8
	MaxLogRecordBytes = 65536
	MaxLogStreams     = 32
	MaxLogBytes       = 4 << 20
	MaxLogPodBytes    = 1 << 20
)

// LogMatch is a log detector's record predicate (ADR-241), evaluated in the
// region: a literal substring or an RE2 regular expression, optionally on
// one JSON field (a dotted path of object keys) instead of the whole record.
// Records longer than MaxRecordBytes are dropped, or with MatchPrefix their
// truncated prefix is matched (never with JSONField: incomplete JSON is not
// evaluated). WindowSeconds is the detector's eventWindow.
type LogMatch struct {
	Pattern        string `json:"pattern"`
	Regexp         bool   `json:"regexp,omitempty"`
	JSONField      string `json:"jsonField,omitempty"`
	MaxRecordBytes int    `json:"maxRecordBytes"`
	MatchPrefix    bool   `json:"matchPrefix,omitempty"`
	WindowSeconds  int64  `json:"windowSeconds"`
}

// Valid checks the structural bounds; the regular expression itself is
// compiled and bounded by the compiler and again by the region.
func (m LogMatch) Valid() bool {
	if m.Pattern == "" || len(m.Pattern) > MaxLogPattern || !utf8.ValidString(m.Pattern) || m.MaxRecordBytes < 1 || m.MaxRecordBytes > MaxLogRecordBytes || m.WindowSeconds < MinProbeWindowSeconds || m.WindowSeconds > MaxProbeWindowSeconds {
		return false
	}
	if m.JSONField == "" {
		return true
	}
	parts := strings.Split(m.JSONField, ".")
	if m.MatchPrefix || len(m.JSONField) > MaxLogJSONField || len(parts) > MaxLogJSONDepth || !utf8.ValidString(m.JSONField) {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// Resource metrics of the metrics API (ADR-241): the Pod's summed container
// CPU usage in cores and memory working set in bytes, and both divided by
// the Pod's finite effective limit.
const (
	MetricCPUCores         = "cpuCores"
	MetricCPUQuotaRatio    = "cpuQuotaRatio"
	MetricMemoryBytes      = "memoryBytes"
	MetricMemoryLimitRatio = "memoryLimitRatio"
)

// Resource sample ages (ADR-241): a sample older than MaxAgeSeconds is
// Unknown.
const (
	MinResourceSampleSeconds = 30
	MaxResourceSampleSeconds = 300
)

// ResourceCondition is a resource detector's level (ADR-241), evaluated in
// the region on the Pod's metrics API sample: metric operator threshold.
type ResourceCondition struct {
	Metric        string  `json:"metric"`
	Operator      string  `json:"operator"`
	Threshold     float64 `json:"threshold"`
	MaxAgeSeconds int64   `json:"maxAgeSeconds"`
}

// Ratio reports whether the metric needs a finite effective limit.
func (c ResourceCondition) Ratio() bool {
	return c.Metric == MetricCPUQuotaRatio || c.Metric == MetricMemoryLimitRatio
}

func (c ResourceCondition) Valid() bool {
	switch c.Metric {
	case MetricCPUCores, MetricCPUQuotaRatio, MetricMemoryBytes, MetricMemoryLimitRatio:
	default:
		return false
	}
	switch c.Operator {
	case "gt", "gte", "lt", "lte":
	default:
		return false
	}
	return c.Threshold >= 0 && c.Threshold <= 1e18 && c.MaxAgeSeconds >= MinResourceSampleSeconds && c.MaxAgeSeconds <= MaxResourceSampleSeconds
}

// Holds reports whether a sampled value satisfies the condition.
func (c ResourceCondition) Holds(v float64) bool {
	switch c.Operator {
	case "gt":
		return v > c.Threshold
	case "gte":
		return v >= c.Threshold
	case "lt":
		return v < c.Threshold
	case "lte":
		return v <= c.Threshold
	}
	return false
}

// RestartRequest names the workload to observe and, for a probe detector
// (ADR-230), the probe type and window whose Event failures the region adds;
// for an alert detector (ADR-231), the label values every matching active
// Alertmanager alert must carry besides the namespace and pod labels; for a
// log or resource detector (ADR-241), its record predicate or condition.
type RestartRequest struct {
	WorkloadRequest
	Probe              string             `json:",omitempty"`
	ProbeWindowSeconds int64              `json:",omitempty"`
	Alert              bool               `json:",omitempty"`
	AlertLabels        map[string]string  `json:",omitempty"`
	Log                *LogMatch          `json:",omitempty"`
	Resource           *ResourceCondition `json:",omitempty"`
}

func (r RestartRequest) Valid() bool {
	if !r.WorkloadRequest.Valid() || r.Kind == "Pod" || !r.Alert && len(r.AlertLabels) != 0 || len(r.AlertLabels) > MaxAlertLabels {
		return false
	}
	if r.Log != nil || r.Resource != nil {
		if r.Probe != "" || r.ProbeWindowSeconds != 0 || r.Alert || r.Log != nil && r.Resource != nil {
			return false
		}
		return r.Log != nil && r.Log.Valid() || r.Resource != nil && r.Resource.Valid()
	}
	for k, v := range r.AlertLabels {
		if !AlertLabelName(k) || v == "" || len(v) > 256 {
			return false
		}
	}
	if r.Probe == "" {
		return r.ProbeWindowSeconds == 0
	}
	if r.Alert {
		return false
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
		p.ProbeFailures >= 0 && p.ProbeFailures <= 1<<31 && (p.ProbeLast == 0 || p.ProbeLast >= MinProbeLast && p.ProbeLast < 1<<31) && (p.ProbeFailures == 0 || p.ProbeLast != 0) &&
		(!p.Unknown || p.ProbeFailures == 0 && p.ProbeLast == 0)
}

// RestartObservation is one complete regional Pod LIST of a named workload.
// A truncated or incomplete LIST is never returned: the region fails instead,
// and the hub treats that as Unknown (no trigger fires).
type RestartObservation struct {
	ClusterID string                     `json:"clusterID"`
	Namespace configuration.NamespaceRef `json:"namespace"`
	Workload  configuration.WorkloadRef  `json:"workload"`
	Pods      []PodRestarts              `json:"pods"`
	// Probe echoes the probe type of a probe observation (ADR-230); Alert
	// marks an alert observation (ADR-231), Log and Resource a log or
	// resource observation (ADR-241).
	Probe                  string `json:"probe,omitempty"`
	Alert                  bool   `json:"alert,omitempty"`
	Log                    bool   `json:"log,omitempty"`
	Resource               bool   `json:"resource,omitempty"`
	ObservedAt, FreshUntil time.Time
}

// Answers reports whether the observation carries exactly the detector data
// the request asked for.
func (o RestartObservation) Answers(r RestartRequest) bool {
	return o.Probe == r.Probe && o.Alert == r.Alert && o.Log == (r.Log != nil) && o.Resource == (r.Resource != nil)
}

func (o RestartObservation) Valid(now time.Time) bool {
	if !authorization.UUID(o.ClusterID) || !identity.Text(o.Namespace.Name, 63) || !identity.Text(o.Namespace.UID, 64) || (o.Workload.Kind != "Deployment" && o.Workload.Kind != "StatefulSet") || !identity.Text(o.Workload.Name, 253) || !identity.Text(o.Workload.UID, 64) || len(o.Pods) > MaxRestartPods || !identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) {
		return false
	}
	if o.Probe != "" && !ProbeType(o.Probe) {
		return false
	}
	levels := 0
	for _, b := range []bool{o.Probe != "", o.Alert, o.Log, o.Resource} {
		if b {
			levels++
		}
	}
	if levels > 1 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range o.Pods {
		if !p.Valid() || seen[p.UID] || levels == 0 && (p.ProbeFailures != 0 || p.ProbeLast != 0) || p.Unknown && !o.Log && !o.Resource || p.Overlong && !o.Log {
			return false
		}
		seen[p.UID] = true
	}
	return true
}
