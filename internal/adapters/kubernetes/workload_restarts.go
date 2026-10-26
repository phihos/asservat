package kubernetes

import (
	"context"
	"encoding/json"
	"strconv"
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
// A truncated or partial LIST fails (ErrLimit/ErrUnavailable): the hub then
// treats the poll as Unknown and fires nothing.
func (c *PodTargets) ObserveWorkloadRestarts(ctx context.Context, r value.WorkloadRequest) (value.RestartObservation, error) {
	var zero value.RestartObservation
	if !r.Valid() || r.Kind == "Pod" || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now().UTC().Truncate(time.Microsecond)
	ns, err := c.namedNamespace(ctx, r.Namespace)
	if err != nil {
		return zero, err
	}
	workload, selector, err := c.namedWorkload(ctx, r)
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
		var finished string
		for _, s := range append(item.Status.InitContainerStatuses, item.Status.ContainerStatuses...) {
			if s.RestartCount < 0 || s.RestartCount > 1<<20 {
				return zero, value.ErrUnavailable
			}
			pod.Restarts += s.RestartCount
			if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
				pod.Waiting = true
			}
			for _, t := range []restartState{s.LastState, s.State} {
				if t.Terminated == nil {
					continue
				}
				// RFC 3339 UTC timestamps order lexically; the latest wins.
				if at := t.Terminated.FinishedAt; at >= finished {
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
