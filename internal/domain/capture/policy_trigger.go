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
}

func (p RestartPolicy) Valid() bool {
	if !authorization.UUID(p.ClusterID) || !identity.Text(p.Namespace, 63) || (p.WorkloadKind != "Deployment" && p.WorkloadKind != "StatefulSet") || !identity.Text(p.WorkloadName, 253) || len(p.Reasons) < 1 || len(p.Reasons) > 3 || !slices.IsSorted(p.Reasons) || len(p.ExitCodes) > 16 || !slices.IsSorted(p.ExitCodes) || p.Interval < time.Second || p.Interval > 24*time.Hour || p.Burst < 1 || p.Burst > 10 || p.RetentionSeconds < 1 || p.RetentionSeconds > privacy.MaxAgeSeconds || p.ObservedPods < 1 || p.ObservedPods > targets.MaxRestartPods {
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
// this one occurrence coalesces.
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
	slices.SortFunc(fired, func(a, b RestartCandidate) int {
		if a.PodUID < b.PodUID {
			return -1
		}
		if a.PodUID > b.PodUID {
			return 1
		}
		return 0
	})
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
	PolicyUID, ActiveID, DeactivatedID   string
	Generation, IntentVersion            int64
	AcceptedIntentVersion                int64
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
}
type PolicyOccurrenceStatus struct {
	ID, CaptureID, Outcome string
	Restarts               int64
	CreatedAt              time.Time
}
type PolicySuppression struct {
	Reason          string
	Count           int64
	FirstAt, LastAt time.Time
}
