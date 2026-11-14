package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

// capacityDeliveryRead bounds the reads of one capacity delivery.
const capacityDeliveryRead = 10 * time.Second

// CapacityDelivery returns the connector cluster's capacity observation for
// the hub (ADR-330): the namespaces carrying at least one of keys, with only
// those labels, and their Deployments, StatefulSets and unowned Pods, read
// with the same metadata pages as the hub cluster's own capacity discovery.
// Deleting objects are left out.
func (c *PermissionClient) CapacityDelivery(ctx context.Context, keys []string) (contracts.CapacityDelivery, error) {
	var out contracts.CapacityDelivery
	if c == nil || ctx == nil || len(keys) < 1 || len(keys) > 256 {
		return out, cfg.ErrInvalid
	}
	for _, k := range keys {
		if len(validation.IsQualifiedName(k)) != 0 {
			return out, cfg.ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, capacityDeliveryRead)
	defer cancel()
	out.Namespaces = []contracts.DeliveredCapacityNamespace{}
	workloads := 0
	for continuation := ""; ; {
		page, err := c.capacityMetadataPage(ctx, "/api/v1/namespaces", "", continuation)
		if err != nil {
			return contracts.CapacityDelivery{}, err
		}
		for _, item := range page.Items {
			if item.DeletionTimestamp != nil || item.DeletionGracePeriodSeconds != nil {
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
			n := contracts.DeliveredCapacityNamespace{Name: item.Name, UID: string(item.UID), ResourceVersion: item.ResourceVersion, Labels: labels, Workloads: []contracts.DeliveredCapacityWorkload{}}
			for _, kind := range []string{"Deployment", "StatefulSet", "Pod"} {
				if n.Workloads, err = c.capacityDeliveryWorkloads(ctx, item.Name, kind, n.Workloads); err != nil {
					return contracts.CapacityDelivery{}, err
				}
			}
			workloads += len(n.Workloads)
			out.Namespaces = append(out.Namespaces, n)
			if len(out.Namespaces) > contracts.CapacityDeliveryNamespaces || workloads > contracts.CapacityDeliveryWorkloads {
				return contracts.CapacityDelivery{}, cfg.ErrLimit
			}
		}
		if continuation = page.Continue; continuation == "" {
			return out, nil
		}
	}
}

func (c *PermissionClient) capacityDeliveryWorkloads(ctx context.Context, namespace, kind string, out []contracts.DeliveredCapacityWorkload) ([]contracts.DeliveredCapacityWorkload, error) {
	path, ok := capacityWorkloadPath(namespace, kind)
	if !ok {
		return nil, cfg.ErrInvalid
	}
	for continuation := ""; ; {
		page, err := c.capacityMetadataPage(ctx, path, namespace, continuation)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			if item.DeletionTimestamp != nil || item.DeletionGracePeriodSeconds != nil || kind == "Pod" && len(item.OwnerReferences) != 0 {
				continue
			}
			out = append(out, contracts.DeliveredCapacityWorkload{Kind: kind, Name: item.Name, UID: string(item.UID), ResourceVersion: item.ResourceVersion})
			if len(out) > contracts.CapacityDeliveryWorkloads {
				return nil, cfg.ErrLimit
			}
		}
		if continuation = page.Continue; continuation == "" {
			return out, nil
		}
	}
}

// DeliveredCapacity checks a connector's delivery and attributes it to the
// authenticated cluster at the hub's admission time (ADR-330). Malformed
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
