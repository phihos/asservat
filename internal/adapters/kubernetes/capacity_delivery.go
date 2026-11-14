package kubernetes

import (
	"sort"
	"strconv"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// CapacityDeliveryFromCache builds the capacity delivery from watched
// metadata (informer caches, ADR-331): the namespaces carrying at least one
// of keys, with only those labels, and their Deployments, StatefulSets and
// unowned Pods. A workload's version is its generation, so status-only
// updates change nothing and send nothing.
func CapacityDeliveryFromCache(keys []string, namespaces, deployments, statefulsets, pods []*metav1.PartialObjectMetadata) (contracts.CapacityDelivery, error) {
	out := contracts.CapacityDelivery{Namespaces: []contracts.DeliveredCapacityNamespace{}}
	if len(keys) < 1 || len(keys) > 256 {
		return out, cfg.ErrInvalid
	}
	byName := map[string]int{}
	for _, item := range namespaces {
		if item == nil || item.DeletionTimestamp != nil {
			continue
		}
		labels := map[string]string{}
		for _, k := range keys {
			if v, ok := item.Labels[k]; ok {
				labels[k] = v
			}
		}
		if len(labels) == 0 {
			continue
		}
		byName[item.Name] = len(out.Namespaces)
		out.Namespaces = append(out.Namespaces, contracts.DeliveredCapacityNamespace{Name: item.Name, UID: string(item.UID), ResourceVersion: item.ResourceVersion, Labels: labels, Workloads: []contracts.DeliveredCapacityWorkload{}})
	}
	workloads := 0
	for _, set := range []struct {
		kind  string
		items []*metav1.PartialObjectMetadata
	}{{"Deployment", deployments}, {"StatefulSet", statefulsets}, {"Pod", pods}} {
		for _, item := range set.items {
			i, ok := byName[item.Namespace]
			if !ok || item.DeletionTimestamp != nil || set.kind == "Pod" && len(item.OwnerReferences) != 0 {
				continue
			}
			n := &out.Namespaces[i]
			n.Workloads = append(n.Workloads, contracts.DeliveredCapacityWorkload{Kind: set.kind, Name: item.Name, UID: string(item.UID), ResourceVersion: "g" + strconv.FormatInt(item.Generation, 10)})
			workloads++
		}
	}
	if len(out.Namespaces) > contracts.CapacityDeliveryNamespaces || workloads > contracts.CapacityDeliveryWorkloads {
		return contracts.CapacityDelivery{}, cfg.ErrLimit
	}
	// Cache order is arbitrary; the digest needs a fixed one.
	sort.Slice(out.Namespaces, func(a, b int) bool { return out.Namespaces[a].Name < out.Namespaces[b].Name })
	for i := range out.Namespaces {
		w := out.Namespaces[i].Workloads
		sort.Slice(w, func(a, b int) bool { return w[a].Kind+"/"+w[a].Name < w[b].Kind+"/"+w[b].Name })
	}
	return out, nil
}

// DeliveredCapacity checks a connector's delivery and attributes it to the
// authenticated cluster at the hub's admission time (ADR-331). Malformed
// names, label keys or values are refused; the hub-worker reads only its
// qualification's keys.
func DeliveredCapacity(cluster string, observedAt time.Time, d contracts.CapacityDelivery) (app.RemoteCapacity, error) {
	out := app.RemoteCapacity{ClusterID: cluster, ObservedAt: observedAt}
	if len(d.Namespaces) > contracts.CapacityDeliveryNamespaces {
		return app.RemoteCapacity{}, cfg.ErrLimit
	}
	for _, n := range d.Namespaces {
		ns := cfg.NamespaceRef{Name: n.Name, UID: n.UID}
		if !namespaceRefValid(ns) || len(n.Labels) == 0 {
			return app.RemoteCapacity{}, cfg.ErrInvalid
		}
		for k, v := range n.Labels {
			if len(validation.IsQualifiedName(k)) != 0 || len(validation.IsValidLabelValue(v)) != 0 {
				return app.RemoteCapacity{}, cfg.ErrInvalid
			}
		}
		m := app.RemoteCapacityNamespace{Namespace: ns, ResourceVersion: n.ResourceVersion, Labels: n.Labels}
		for _, w := range n.Workloads {
			if len(validation.IsDNS1123Subdomain(w.Name)) != 0 {
				return app.RemoteCapacity{}, cfg.ErrInvalid
			}
			m.Workloads = append(m.Workloads, app.RemoteCapacityWorkload{Workload: cfg.WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID}, ResourceVersion: w.ResourceVersion})
		}
		out.Namespaces = append(out.Namespaces, m)
	}
	if !out.Valid() {
		return app.RemoteCapacity{}, cfg.ErrInvalid
	}
	return out, nil
}
