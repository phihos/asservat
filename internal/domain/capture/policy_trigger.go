package capture

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// ADR-228 restart trigger: the first S-03 increment accepts exactly one
// DebugPolicy shape. A single exit detector on a named Deployment or
// StatefulSet fires the pod-status context diagnostic on the triggering Pod.
// Every other detector, action or option is rejected with its field path.

// WorkloadTriggerInterval and WorkloadTriggerBurst are the installation-wide
// trigger budget of one workload (REQ-TRG-004 default): one occurrence per
// five minutes with a burst of two, shared by every policy on the workload.
const (
	WorkloadTriggerInterval = 5 * time.Minute
	WorkloadTriggerBurst    = 2
	// TriggerPollInterval is the restart poll period of one active policy.
	TriggerPollInterval = 15 * time.Second
	// MaxActivePoliciesPerCluster bounds polling queries per workload cluster.
	MaxActivePoliciesPerCluster = 16
)

// RestartPolicy is the compiled, accepted subset. It contains configuration
// intent only; executor, delegation and limits come from protected acceptance.
type RestartPolicy struct {
	ClusterID, Namespace, WorkloadKind, WorkloadName string
	// Reasons is a sorted subset of OOMKilled, Error and CrashLoopBackOff.
	Reasons []string
	// ExitCodes is sorted; empty matches every exit code.
	ExitCodes []int32
	// The policy's own budget. The shared workload budget always applies too,
	// so a policy can only tighten it.
	Interval         time.Duration
	Burst            int
	RetentionSeconds int64
	ObservedPods     int
	// Detector is empty for the ADR-228 exit detector or DetectorProbe
	// (ADR-230). The probe fields are empty for an exit detector, so an exit
	// policy's scope digest is unchanged by them.
	Detector        string        `json:",omitempty"`
	ProbeType       string        `json:",omitempty"`
	MinimumFailures int           `json:",omitempty"`
	ProbeWindow     time.Duration `json:",omitempty"`
	// AlertLabels are an alert detector's (ADR-231) label matchers besides
	// namespace and pod; empty for every other detector.
	AlertLabels map[string]string `json:",omitempty"`
	// Log and Resource are a log or resource detector's (ADR-241) record
	// predicate or condition; nil for every other detector, so other
	// policies' scope digests are unchanged.
	Log      *targets.LogMatch          `json:",omitempty"`
	Resource *targets.ResourceCondition `json:",omitempty"`
	// Sharing is the optional spec.sharing block (ADR-239). It is nil for a
	// policy without one, so such a policy's scope digest is unchanged.
	Sharing *PolicySharing `json:",omitempty"`
}

// Detector kinds stored with watermarks and occurrences (migrations 00084
// and 00085).
const (
	DetectorExit  = "exit"
	DetectorProbe = "probe"
	DetectorAlert = "alert"
	// DetectorLog and DetectorResource are ADR-241's (migration 00094).
	DetectorLog      = "log"
	DetectorResource = "resource"
)

// AlertReceiver is the only alert receiverRef of this release (ADR-231): the
// target cluster's configured in-cluster Alertmanager.
const AlertReceiver = "alertmanager"

// Kind is the compiled detector kind: exit or probe.
func (p RestartPolicy) Kind() string {
	if p.Detector == "" {
		return DetectorExit
	}
	return p.Detector
}

// Request is the regional observation this policy needs: the workload's Pod
// LIST and, for a probe detector, its probe Events; for an alert detector,
// its Alertmanager label matchers.
func (p RestartPolicy) Request() targets.RestartRequest {
	r := targets.RestartRequest{WorkloadRequest: targets.WorkloadRequest{ClusterID: p.ClusterID, Namespace: p.Namespace, Kind: p.WorkloadKind, Name: p.WorkloadName}}
	switch p.Detector {
	case DetectorProbe:
		r.Probe, r.ProbeWindowSeconds = p.ProbeType, int64(p.ProbeWindow/time.Second)
	case DetectorAlert:
		r.Alert = true
		if len(p.AlertLabels) > 0 {
			r.AlertLabels = make(map[string]string, len(p.AlertLabels))
			for k, v := range p.AlertLabels {
				r.AlertLabels[k] = v
			}
		}
	case DetectorLog:
		if p.Log != nil {
			m := *p.Log
			r.Log = &m
		}
	case DetectorResource:
		if p.Resource != nil {
			c := *p.Resource
			r.Resource = &c
		}
	}
	return r
}

func (p RestartPolicy) Valid() bool {
	if !authorization.UUID(p.ClusterID) || !identity.Text(p.Namespace, 63) || (p.WorkloadKind != "Deployment" && p.WorkloadKind != "StatefulSet") || !identity.Text(p.WorkloadName, 253) || p.Interval < time.Second || p.Interval > 24*time.Hour || p.Burst < 1 || p.Burst > 10 || p.RetentionSeconds < 1 || p.RetentionSeconds > privacy.MaxAgeSeconds || p.ObservedPods < 1 || p.ObservedPods > targets.MaxRestartPods {
		return false
	}
	if p.Detector != DetectorAlert && len(p.AlertLabels) != 0 || p.Sharing != nil && !p.Sharing.Valid() || (p.Detector == DetectorLog) != (p.Log != nil) || (p.Detector == DetectorResource) != (p.Resource != nil) {
		return false
	}
	switch p.Detector {
	case DetectorLog, DetectorResource:
		return len(p.Reasons) == 0 && len(p.ExitCodes) == 0 && p.ProbeType == "" && p.MinimumFailures == 0 && p.ProbeWindow == 0 && p.Request().Valid()
	case DetectorAlert:
		return len(p.Reasons) == 0 && len(p.ExitCodes) == 0 && p.ProbeType == "" && p.MinimumFailures == 0 && p.ProbeWindow == 0 && p.Request().Valid()
	case DetectorProbe:
		return len(p.Reasons) == 0 && len(p.ExitCodes) == 0 && targets.ProbeType(p.ProbeType) && p.MinimumFailures >= 1 && p.MinimumFailures <= 1000 && p.ProbeWindow%time.Second == 0 && p.ProbeWindow >= targets.MinProbeWindowSeconds*time.Second && p.ProbeWindow <= targets.MaxProbeWindowSeconds*time.Second
	case "":
	default:
		return false
	}
	if p.ProbeType != "" || p.MinimumFailures != 0 || p.ProbeWindow != 0 || len(p.Reasons) < 1 || len(p.Reasons) > 3 || !slices.IsSorted(p.Reasons) || len(p.ExitCodes) > 16 || !slices.IsSorted(p.ExitCodes) {
		return false
	}
	for i, r := range p.Reasons {
		if (r != "CrashLoopBackOff" && r != "Error" && r != "OOMKilled") || i > 0 && p.Reasons[i-1] == r {
			return false
		}
	}
	for i, c := range p.ExitCodes {
		if c < 0 || c > 255 || i > 0 && p.ExitCodes[i-1] == c {
			return false
		}
	}
	return true
}

// Matches reports whether a Pod's latest termination satisfies the detector.
func (p RestartPolicy) Matches(r targets.PodRestarts) bool {
	reason := slices.Contains(p.Reasons, r.Reason) || r.Waiting && slices.Contains(p.Reasons, "CrashLoopBackOff")
	return reason && (len(p.ExitCodes) == 0 || slices.Contains(p.ExitCodes, r.ExitCode))
}

// PolicyFieldError names the first rejected DebugPolicy field.
type PolicyFieldError struct{ Path, Reason string }

func (e PolicyFieldError) Error() string { return e.Path + ": " + e.Reason }
func (e PolicyFieldError) Unwrap() error { return ErrInvalid }

// RestartCandidate is one Pod whose restart counter rose and whose latest
// termination matches. Missed counts the restarts between two polls that
// this one occurrence coalesces. For a probe detector Restarts is the newest
// failure second (the occurrence key) and Missed is zero.
type RestartCandidate struct {
	PodUID           string
	Restarts, Missed int64
}

// RestartDelta is the pure trigger evaluation of one complete observation.
// previous maps Pod UID to its last restart count. The first observation of
// a Pod is only its baseline; next holds only the observed Pods (the store
// keeps unobserved rows and prunes them after ten minutes); a counter is
// monotonic per UID, so a replayed or older observation never fires.
func RestartDelta(p RestartPolicy, previous map[string]int64, o targets.RestartObservation) (next map[string]int64, fired []RestartCandidate) {
	next = make(map[string]int64, len(o.Pods))
	for _, pod := range o.Pods {
		before, known := previous[pod.UID]
		next[pod.UID] = max(before, pod.Restarts)
		if known && pod.Restarts > before && p.Matches(pod) {
			fired = append(fired, RestartCandidate{PodUID: pod.UID, Restarts: pod.Restarts, Missed: pod.Restarts - before - 1})
		}
	}
	sortCandidates(fired)
	return next, fired
}

func sortCandidates(fired []RestartCandidate) {
	slices.SortFunc(fired, func(a, b RestartCandidate) int {
		if a.PodUID < b.PodUID {
			return -1
		}
		if a.PodUID > b.PodUID {
			return 1
		}
		return 0
	})
}

// PodMark is one Pod's watermark: the restart count (exit) or the newest
// probe failure second (probe), and for a probe whether its level re-armed.
type PodMark struct {
	Value int64
	Armed bool
}

// TriggerDelta evaluates one complete observation for the policy's detector.
// previous holds only watermarks of this detector kind; a watermark of
// another kind is unknown, so the Pod is a new baseline.
func TriggerDelta(p RestartPolicy, previous map[string]PodMark, o targets.RestartObservation) (next map[string]PodMark, fired []RestartCandidate) {
	if p.Kind() == DetectorExit {
		counts := make(map[string]int64, len(previous))
		for pod, m := range previous {
			counts[pod] = m.Value
		}
		values, fired := RestartDelta(p, counts, o)
		next = make(map[string]PodMark, len(values))
		for pod, v := range values {
			next[pod] = PodMark{Value: v, Armed: true}
		}
		return next, fired
	}
	return ProbeDelta(p, previous, o)
}

// ProbeDelta is the probe detector's level evaluation (ADR-230). A Pod is
// failing while at least MinimumFailures failures fall in the window. One
// occurrence fires on a rising edge, keyed by the newest failure second; the
// Pod then re-arms only at an observation with an empty window, which proves
// a window without failure. The first observation of a Pod is its baseline,
// armed only if its window is empty, so a probe already failing at activation
// waits for a proven recovery.
//
// The alert detector (ADR-231) uses the same level: a Pod is failing while
// at least one matching alert is active, keyed by the newest alert's
// startsAt second, and re-arms at the first poll with no matching alert.
//
// The log detector (ADR-241) is a level over the matching records within
// its eventWindow, keyed by the newest match second; the resource detector
// a level over its condition, keyed by the metrics sample second. A Pod
// reported Unknown keeps its previous watermark: it neither fires, re-arms
// nor becomes a baseline.
func ProbeDelta(p RestartPolicy, previous map[string]PodMark, o targets.RestartObservation) (next map[string]PodMark, fired []RestartCandidate) {
	threshold := int64(max(p.MinimumFailures, 1))
	next = make(map[string]PodMark, len(o.Pods))
	for _, pod := range o.Pods {
		before, known := previous[pod.UID]
		if pod.Unknown {
			if known {
				next[pod.UID] = before
			}
			continue
		}
		if !known {
			next[pod.UID] = PodMark{Value: pod.ProbeLast, Armed: pod.ProbeFailures == 0}
			continue
		}
		m := PodMark{Value: max(before.Value, pod.ProbeLast), Armed: before.Armed}
		switch {
		case pod.ProbeFailures == 0:
			m.Armed = true
		case before.Armed && pod.ProbeFailures >= threshold && pod.ProbeLast > before.Value:
			fired = append(fired, RestartCandidate{PodUID: pod.UID, Restarts: pod.ProbeLast})
			m.Armed = false
		}
		next[pod.UID] = m
	}
	sortCandidates(fired)
	return next, fired
}

// PolicyTick is one complete restart observation of an accepted policy.
type PolicyTick struct {
	Policy      RestartPolicy
	Authority   authorization.AcceptedPolicyAuthority
	Observation targets.RestartObservation
}

// PolicyOccurrence is one admitted trigger occurrence. Its ID is the capture
// request's idempotency key; it is never re-admitted or retried.
type PolicyOccurrence struct {
	ID, PolicyUID, PodUID string
	Restarts              int64
}

// ActivePolicy names one accepted, unexpired, undeleted policy to poll.
type ActivePolicy struct{ PolicyUID, Name, NamespaceUID string }

// PolicyStatus is the content-free explanation of one policy (REQ-TRG-005):
// counters, the latest occurrences and suppression summaries. It contains no
// Pod names, log text or labels; callers authorize it separately.
type PolicyStatus struct {
	// ActiveID is the current acceptance; DeactivatedID is the latest
	// acceptance of a deactivated policy (ADR-229). At most one is set.
	PolicyUID, ActiveID, DeactivatedID string
	Generation, IntentVersion          int64
	AcceptedIntentVersion              int64
	// AcceptedGeneration is the DebugPolicy generation the acceptance named.
	AcceptedGeneration                   int64
	Suspended, Deleted                   bool
	Creator                              *identity.Principal
	ExecutionsSpent, MaxExecutions       int64
	NotAfter                             time.Time
	WatchedPods, Occurrences, Captured   int64
	Recent                               []PolicyOccurrenceStatus
	Suppressions                         []PolicySuppression
	ClusterID, NamespaceUID, WorkloadUID string
	Authority                            authorization.AcceptedPolicyAuthority
	SourceObservedAt, SourceFreshUntil   time.Time
	// Detector describes the current DebugPolicy's detector, if it compiles.
	Detector *PolicyDetector
	// Sharing is the acceptance's recurring sharing (ADR-239), if any.
	Sharing *PolicySharingStatus
}

// PolicyDetector is a compiled detector's configuration for status display
// (ADR-230); it contains no observed content.
type PolicyDetector struct {
	Kind            string
	Reasons         []string
	ExitCodes       []int32
	ProbeType       string
	MinimumFailures int
	WindowSeconds   int64
	// LogMatch is a log detector's match mode (literal or regexp) and LogJSON
	// whether it matches a JSON field; the pattern itself is not repeated
	// (ADR-241).
	LogMatch string
	LogJSON  bool
	// Resource is a resource detector's condition (ADR-241).
	Resource *targets.ResourceCondition
}

// Describe returns the policy's detector configuration.
func (p RestartPolicy) Describe() PolicyDetector {
	d := PolicyDetector{Kind: p.Kind(), Reasons: slices.Clone(p.Reasons), ExitCodes: slices.Clone(p.ExitCodes), ProbeType: p.ProbeType, MinimumFailures: p.MinimumFailures, WindowSeconds: int64(p.ProbeWindow / time.Second)}
	if p.Log != nil {
		d.LogMatch, d.LogJSON, d.WindowSeconds = "literal", p.Log.JSONField != "", p.Log.WindowSeconds
		if p.Log.Regexp {
			d.LogMatch = "regexp"
		}
	}
	if p.Resource != nil {
		c := *p.Resource
		d.Resource = &c
	}
	return d
}

// PolicyOccurrenceStatus is one recent occurrence. Restarts is the restart
// count of an exit occurrence, the failure second of a probe occurrence,
// the alert startsAt second of an alert occurrence (ADR-231), the newest
// matching record second of a log occurrence or the metrics sample second
// of a resource occurrence (ADR-241).

type PolicyOccurrenceStatus struct {
	ID, CaptureID, Outcome, Detector string
	Restarts                         int64
	CreatedAt                        time.Time
}
type PolicySuppression struct {
	Reason          string
	Count           int64
	FirstAt, LastAt time.Time
}
