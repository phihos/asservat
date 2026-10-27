package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/api/resource"
)

// resourceMetricItems bounds the PodMetrics LIST of a resource observation:
// the workload selector may match other workloads' Pods, and the metrics API
// does not page.
const resourceMetricItems = 1024

// resourceLevels adds the ADR-241 resource level to the observed Pods from
// one metrics.k8s.io PodMetrics LIST of the workload's selector. A Pod's
// value is the sum over its containers of CPU usage (cores) or memory
// working set (bytes), optionally divided by its finite effective limit:
// the Pod-level limit if set, otherwise the sum of every container's limit.
// Only a level (one when the condition holds) and the sample second leave
// the region. A Pod without a sample, with a sample older than the
// condition's age bound or than the Pod's start, or whose sample misses a
// running container is Unknown. The metrics API being absent (404) is
// ErrUnsupported and unavailable (503) ErrUnavailable, never zero; a ratio
// on a Pod without a finite limit is ErrUnsupported (a capability gap).
func (c *PodTargets) resourceLevels(ctx context.Context, namespace, selector string, condition value.ResourceCondition, now time.Time, pods []value.PodRestarts, items []restartPodItem) error {
	if !condition.Valid() {
		return value.ErrInvalid
	}
	if len(pods) == 0 {
		return nil
	}
	raw, err := c.client.raw(ctx, "/apis/metrics.k8s.io/v1beta1/namespaces/"+namespace+"/pods", map[string]string{"labelSelector": selector})
	if err != nil {
		if err == cfg.ErrChanged {
			return value.ErrUnsupported
		}
		return targetReadError(err)
	}
	var list struct {
		APIVersion, Kind string
		Items            []struct {
			Metadata struct {
				Name, Namespace string
			}
			Timestamp  string
			Containers []struct {
				Name  string
				Usage map[string]string
			}
		}
	}
	if json.Unmarshal(raw, &list) != nil || list.APIVersion != "metrics.k8s.io/v1beta1" || list.Kind != "PodMetricsList" || list.Items == nil {
		return value.ErrUnavailable
	}
	if len(list.Items) > resourceMetricItems {
		return value.ErrLimit
	}
	index := make(map[string]int, len(pods))
	for i, p := range pods {
		index[p.Name] = i
		pods[i].Unknown = true
	}
	limits := make([]float64, len(pods))
	if condition.Ratio() {
		name := "cpu"
		if condition.Metric == value.MetricMemoryLimitRatio {
			name = "memory"
		}
		for i, item := range items {
			limit, ok := podLimit(item, name)
			if !ok {
				return value.ErrUnsupported
			}
			limits[i] = limit
		}
	}
	seen := map[string]bool{}
	for _, m := range list.Items {
		i, owned := index[m.Metadata.Name]
		if !owned || m.Metadata.Namespace != namespace {
			continue
		}
		if seen[m.Metadata.Name] {
			return value.ErrUnavailable
		}
		seen[m.Metadata.Name] = true
		sampled, err := time.Parse(time.RFC3339Nano, m.Timestamp)
		if err != nil {
			return value.ErrUnavailable
		}
		// The sample time comes from metrics-server's scrape: a future time
		// would raise the watermark past later samples, so it counts as now.
		if sampled.After(now) {
			sampled = now
		}
		started, err := time.Parse(time.RFC3339, items[i].Status.StartTime)
		if err != nil || sampled.Before(started) || now.Sub(sampled) > time.Duration(condition.MaxAgeSeconds)*time.Second || sampled.Unix() < value.MinProbeLast || sampled.Unix() >= 1<<31 {
			// No start time, a sample of a previous Pod of the same name, or
			// a stale sample: Unknown.
			continue
		}
		containers := podContainers(items[i])
		covered := map[string]bool{}
		var total float64
		valid := true
		for _, ct := range m.Containers {
			if covered[ct.Name] {
				return value.ErrUnavailable
			}
			if !containers[ct.Name] {
				// A sample of another Pod of the same name: Unknown.
				valid = false
				break
			}
			covered[ct.Name] = true
			key := "cpu"
			if condition.Metric == value.MetricMemoryBytes || condition.Metric == value.MetricMemoryLimitRatio {
				key = "memory"
			}
			q, err := resource.ParseQuantity(ct.Usage[key])
			if err != nil || q.Sign() < 0 {
				return value.ErrUnavailable
			}
			total += q.AsApproximateFloat64()
		}
		if !valid {
			continue
		}

		missing := false
		for _, s := range append(append([]restartContainerStatus{}, items[i].Status.InitContainerStatuses...), items[i].Status.ContainerStatuses...) {
			if s.State.Running != nil && !covered[s.Name] {
				missing = true
			}
		}
		if missing {
			continue
		}
		if condition.Ratio() {
			total /= limits[i]
		}
		p := &pods[i]
		p.Unknown = false
		if condition.Holds(total) {
			p.ProbeFailures, p.ProbeLast = 1, sampled.Unix()
		}
	}
	return nil
}

// podContainers names a Pod's containers and init containers.
func podContainers(item restartPodItem) map[string]bool {
	out := map[string]bool{}
	for _, ct := range append(append([]restartContainer{}, item.Spec.InitContainers...), item.Spec.Containers...) {
		out[ct.Name] = true
	}
	return out
}

// podLimit is the Pod's finite effective limit of one resource in cores or
// bytes: the Pod-level limit if set, otherwise the sum of the limits of
// every container and restartable (sidecar) init container, all of which
// must be finite. Other init containers do not run alongside them.
func podLimit(item restartPodItem, name string) (float64, bool) {
	parse := func(limits map[string]string) (float64, bool) {
		q, err := resource.ParseQuantity(limits[name])
		if err != nil || q.Sign() <= 0 {
			return 0, false
		}
		return q.AsApproximateFloat64(), true
	}
	if item.Spec.Resources != nil && item.Spec.Resources.Limits[name] != "" {
		return parse(item.Spec.Resources.Limits)
	}
	var total float64
	running := append([]restartContainer{}, item.Spec.Containers...)
	for _, ct := range item.Spec.InitContainers {
		if ct.RestartPolicy == "Always" {
			running = append(running, ct)
		}
	}
	if len(running) == 0 {
		return 0, false
	}
	for _, ct := range running {
		v, ok := parse(ct.Resources.Limits)
		if !ok {
			return 0, false
		}
		total += v
	}
	return total, true
}
