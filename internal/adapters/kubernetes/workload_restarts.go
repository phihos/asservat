package kubernetes

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

// restartOwnerSets bounds the distinct ReplicaSets one Deployment observation
// verifies; a rollout normally has one or two.
const restartOwnerSets = 8

type restartPodItem struct {
	Metadata struct {
		Name, Namespace, UID string
		Labels               map[string]string
		DeletionTimestamp    *string
		OwnerReferences      []struct {
			APIVersion, Kind, Name, UID string
			Controller                  *bool
		}
	}
	Status struct {
		ContainerStatuses, InitContainerStatuses []restartContainerStatus
	}
}

type restartContainerStatus struct {
	RestartCount int64
	State        restartState
	LastState    restartState
}

type restartState struct {
	Waiting *struct {
		Reason string
	}
	Terminated *struct {
		Reason     string
		ExitCode   int32
		FinishedAt string
	}
}

// ObserveWorkloadRestarts lists one named workload's Pods once (ADR-228). It
// reads the namespace, the workload, one bounded Pod LIST and the owning
// ReplicaSets of a Deployment: no new privilege beyond workload resolution.
// A probe request (ADR-230) adds one namespace Event LIST (Events `list`).
// A truncated or partial LIST fails (ErrLimit/ErrUnavailable): the hub then
// treats the poll as Unknown and fires nothing.
func (c *PodTargets) ObserveWorkloadRestarts(ctx context.Context, r value.RestartRequest) (value.RestartObservation, error) {
	var zero value.RestartObservation
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now().UTC().Truncate(time.Microsecond)
	ns, err := c.namedNamespace(ctx, r.Namespace)
	if err != nil {
		return zero, err
	}
	workload, selector, err := c.namedWorkload(ctx, r.WorkloadRequest)
	if err != nil {
		return zero, err
	}
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+ns.Name+"/pods", map[string]string{"labelSelector": selector.String(), "limit": strconv.Itoa(value.MaxRestartPods + 1)})
	if err != nil {
		return zero, targetReadError(err)
	}
	var list struct {
		APIVersion, Kind string
		Metadata         struct {
			ResourceVersion    string
			Continue           string
			RemainingItemCount *int64
		}
		Items []restartPodItem
	}
	if json.Unmarshal(raw, &list) != nil || list.APIVersion != "v1" || list.Kind != "PodList" || !identity.Text(list.Metadata.ResourceVersion, 128) || list.Items == nil {
		return zero, value.ErrUnavailable
	}
	if list.Metadata.Continue != "" || len(list.Items) > value.MaxRestartPods || list.Metadata.RemainingItemCount != nil && *list.Metadata.RemainingItemCount != 0 {
		return zero, value.ErrLimit
	}
	owned := map[string]bool{}
	out := value.RestartObservation{ClusterID: r.ClusterID, Namespace: ns, Workload: workload, Pods: []value.PodRestarts{}}
	seen := map[string]bool{}
	for _, item := range list.Items {
		m := item.Metadata
		if len(validation.IsDNS1123Subdomain(m.Name)) != 0 || !identity.Text(m.UID, 64) || m.Namespace != ns.Name || seen[m.UID] || !selector.Matches(labels.Set(m.Labels)) {
			return zero, value.ErrUnavailable
		}
		seen[m.UID] = true
		if m.DeletionTimestamp != nil {
			continue
		}
		var controller *struct{ APIVersion, Kind, Name, UID string }
		for _, o := range m.OwnerReferences {
			if o.Controller != nil && *o.Controller {
				if controller != nil {
					return zero, value.ErrUnavailable
				}
				o := o
				controller = &struct{ APIVersion, Kind, Name, UID string }{o.APIVersion, o.Kind, o.Name, o.UID}
			}
		}
		if controller == nil || controller.APIVersion != "apps/v1" {
			continue
		}
		switch {
		case workload.Kind == "StatefulSet":
			if controller.Kind != "StatefulSet" || controller.UID != workload.UID {
				continue
			}
		case controller.Kind == "ReplicaSet":
			mine, known := owned[controller.UID]
			if !known {
				if len(owned) >= restartOwnerSets || len(validation.IsDNS1123Subdomain(controller.Name)) != 0 {
					return zero, value.ErrLimit
				}
				rs, err := c.object(ctx, "/apis/apps/v1/namespaces/"+ns.Name+"/replicasets/"+controller.Name, "ReplicaSet", ns.Name, controller.Name, controller.UID)
				if err != nil {
					return zero, err
				}
				mine = ownerMatches(rs.owner, workload.Kind, workload.Name, workload.UID)
				owned[controller.UID] = mine
			}
			if !mine {
				continue
			}
		default:
			continue
		}
		pod := value.PodRestarts{Name: m.Name, UID: m.UID}
		// Attribution is the most recent termination across the Pod's
		// containers (whole-pod scope); container identity is not a filter.
		var finished time.Time
		for _, s := range append(item.Status.InitContainerStatuses, item.Status.ContainerStatuses...) {
			if s.RestartCount < 0 || s.RestartCount > 1<<20 {
				return zero, value.ErrUnavailable
			}
			pod.Restarts += s.RestartCount
			if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
				pod.Waiting = true
			}
			for _, t := range []restartState{s.LastState, s.State} {
				if t.Terminated == nil || t.Terminated.FinishedAt == "" {
					continue
				}
				at, err := time.Parse(time.RFC3339, t.Terminated.FinishedAt)
				if err != nil {
					return zero, value.ErrUnavailable
				}
				if finished.IsZero() || at.After(finished) {
					finished = at
					pod.Reason, pod.ExitCode = restartReason(t.Terminated.Reason), t.Terminated.ExitCode
				}
			}
		}
		if pod.ExitCode < 0 || pod.ExitCode > 255 {
			pod.ExitCode = 255
		}
		out.Pods = append(out.Pods, pod)
	}
	if r.Probe != "" {
		if err = c.probeFailures(ctx, ns.Name, r, start, out.Pods); err != nil {
			return zero, err
		}
		out.Probe = r.Probe
	}
	out.ObservedAt = start
	out.FreshUntil = start.Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		out.FreshUntil = identity.Earlier(out.FreshUntil, deadline.UTC().Truncate(time.Microsecond))
	}
	if c.client.current(ctx, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

// restartReason keeps the closed reasons a trigger can name; any other
// runtime-specific reason is reported as Other.
func restartReason(reason string) string {
	switch reason {
	case "OOMKilled", "Error", "Completed", "ContainerCannotRun", "DeadlineExceeded":
		return reason
	case "":
		return ""
	default:
		return "Other"
	}
}

// probeEventLimit and probeEventPages bound the Event LIST of a probe
// observation (the selector is namespace-wide, so neighbours count); a
// namespace with more Unhealthy Pod Events is not observed (Unknown).
const (
	probeEventLimit = 512
	probeEventPages = 4
)

type probeEventTime struct{ time.Time }

func (t *probeEventTime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	v, err := time.Parse(time.RFC3339Nano, s)
	t.Time = v
	return err
}

// probeFailures adds the ADR-230 probe data to the observed Pods from one
// namespace Event LIST of kubelet Unhealthy Pod Events. Only the involved
// Pod UID, the probe-type prefix of the message, counts and timestamps are
// read; message text is never returned or kept. For each Pod it reports the
// newest matching failure second and a proven lower bound of failures in
// the window: an Event series that started inside the window counts all its
// failures, one that started earlier counts only its latest. A LIST longer than
// probeEventPages pages, truncated or malformed fails, so the poll is Unknown. A series
// that started before the window proves only one failure in it, so a
// minimumFailures above one fires only for failures that began inside the
// window (ADR-230).
func (c *PodTargets) probeFailures(ctx context.Context, namespace string, r value.RestartRequest, now time.Time, pods []value.PodRestarts) error {
	index := make(map[string]int, len(pods))
	for i, p := range pods {
		index[p.UID] = i
	}
	params := map[string]string{"fieldSelector": "involvedObject.kind=Pod,reason=Unhealthy", "limit": strconv.Itoa(probeEventLimit)}
	for page := 0; page < probeEventPages; page++ {
		next, err := c.probeEventPage(ctx, namespace, params, index, r, now, pods)
		if err != nil || next == "" {
			return err
		}
		params["continue"] = next
	}
	return value.ErrLimit
}

// probeEventPage reads one Event LIST page into pods and returns its
// continue token.
func (c *PodTargets) probeEventPage(ctx context.Context, namespace string, params map[string]string, index map[string]int, r value.RestartRequest, now time.Time, pods []value.PodRestarts) (string, error) {
	raw, err := c.client.raw(ctx, "/api/v1/namespaces/"+namespace+"/events", params)
	if err != nil {
		return "", targetReadError(err)
	}
	var list struct {
		APIVersion, Kind string
		Metadata         struct {
			Continue           string
			RemainingItemCount *int64
		}
		Items []struct {
			InvolvedObject struct{ Kind, UID string }
			Reason         string
			Message        string
			Count          int64
			FirstTimestamp probeEventTime
			LastTimestamp  probeEventTime
			EventTime      probeEventTime
			Series         *struct {
				Count            int64
				LastObservedTime probeEventTime
			}
		}
	}
	if json.Unmarshal(raw, &list) != nil || list.APIVersion != "v1" || list.Kind != "EventList" || list.Items == nil {
		return "", value.ErrUnavailable
	}
	if len(list.Items) > probeEventLimit || list.Metadata.Continue == "" && list.Metadata.RemainingItemCount != nil && *list.Metadata.RemainingItemCount != 0 {
		return "", value.ErrLimit
	}
	failed, errored := r.Probe+" probe failed", r.Probe+" probe errored"
	windowStart := now.Unix() - r.ProbeWindowSeconds
	for _, e := range list.Items {
		i, owned := index[e.InvolvedObject.UID]
		if !owned || e.InvolvedObject.Kind != "Pod" || e.Reason != "Unhealthy" || !strings.HasPrefix(e.Message, failed) && !strings.HasPrefix(e.Message, errored) {
			continue
		}
		count, last, first := e.Count, e.LastTimestamp.Time, e.FirstTimestamp.Time
		if e.Series != nil {
			count = max(count, e.Series.Count)
			if e.Series.LastObservedTime.After(last) {
				last = e.Series.LastObservedTime.Time
			}
		}
		if e.EventTime.After(last) {
			last = e.EventTime.Time
		}
		if first.IsZero() {
			first = e.EventTime.Time
		}
		if last.Unix() < value.MinProbeLast || last.Unix() >= 1<<31 || count < 0 || count > 1<<31 {
			return "", value.ErrUnavailable
		}
		// Event times come from node clocks: a future time would raise the
		// watermark past later real failures, so it counts as now.
		if last.After(now) {
			last = now
		}
		count = max(count, 1)
		p := &pods[i]
		p.ProbeLast = max(p.ProbeLast, last.Unix())
		if last.Unix() > windowStart {
			if first.IsZero() || first.Unix() <= windowStart {
				count = 1
			}
			p.ProbeFailures = min(p.ProbeFailures+count, 1<<31)
		}
	}
	return list.Metadata.Continue, nil
}
