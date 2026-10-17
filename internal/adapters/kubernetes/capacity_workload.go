package kubernetes

import (
	"context"
	"encoding/json"
	"strconv"

	app "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const capacityMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
const capacityMetadataListAccept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"

var _ app.CapacityWorkloadReader = (*PermissionClient)(nil)

func capacityWorkloadPath(namespace, kind string) (string, bool) {
	if len(validation.IsDNS1123Label(namespace)) != 0 {
		return "", false
	}
	switch kind {
	case "Deployment":
		return "/apis/apps/v1/namespaces/" + namespace + "/deployments", true
	case "StatefulSet":
		return "/apis/apps/v1/namespaces/" + namespace + "/statefulsets", true
	case "Pod":
		return "/api/v1/namespaces/" + namespace + "/pods", true
	default:
		return "", false
	}
}
func capacityMetadataValid(m metav1.ObjectMeta, namespace string) bool {
	return len(validation.IsDNS1123Subdomain(m.Name)) == 0 && identity.Text(string(m.UID), 64) && identity.Text(m.ResourceVersion, 128) && m.Namespace == namespace && m.DeletionTimestamp == nil && m.DeletionGracePeriodSeconds == nil
}
func (c *PermissionClient) capacityMetadataPage(ctx context.Context, path, namespace, continuation string) (metav1.PartialObjectMetadataList, error) {
	var out metav1.PartialObjectMetadataList
	if c == nil || ctx == nil || ctx.Err() != nil || len(continuation) > 8192 {
		return out, cfg.ErrInvalid
	}
	start := c.now()
	until := start.Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	r := c.api.Get().AbsPath(path).MaxRetries(0).SetHeader("Accept", capacityMetadataListAccept).Param("limit", strconv.Itoa(app.CapacityDiscoveryPageSize))
	if continuation != "" {
		r.Param("continue", continuation)
	}
	b, e := r.DoRaw(live)
	if e != nil {
		return out, permissionError(live, e)
	}
	if permissionJSON(b, permissionPageBytes, 131072) != nil || json.Unmarshal(b, &out) != nil || out.APIVersion != "meta.k8s.io/v1" || out.Kind != "PartialObjectMetadataList" || !identity.Text(out.ResourceVersion, 128) || len(out.Continue) > 8192 || len(out.Items) > app.CapacityDiscoveryPageSize || out.Continue != "" && out.Continue == continuation {
		return metav1.PartialObjectMetadataList{}, cfg.ErrUnavailable
	}
	seen := map[string]bool{}
	for _, item := range out.Items {
		// Deleting objects may occur in a complete candidate page. They are
		// skipped by discovery and never passed to effect observation.
		m := item.ObjectMeta
		m.DeletionTimestamp = nil
		m.DeletionGracePeriodSeconds = nil
		if !capacityMetadataValid(m, namespace) || seen[string(m.UID)] {
			return metav1.PartialObjectMetadataList{}, cfg.ErrUnavailable
		}
		seen[string(m.UID)] = true
	}
	if live.Err() != nil || c.current(live, start, app.CapacitySourceInterval) != nil || !c.now().Before(until) {
		return metav1.PartialObjectMetadataList{}, cfg.ErrUnavailable
	}
	return out, nil
}
func (c *PermissionClient) DiscoverCapacityNamespaces(ctx context.Context, continuation string) (app.CapacityNamespacePage, error) {
	page, e := c.capacityMetadataPage(ctx, "/api/v1/namespaces", "", continuation)
	if e != nil {
		return app.CapacityNamespacePage{}, e
	}
	out := app.CapacityNamespacePage{ResourceVersion: page.ResourceVersion, Continue: page.Continue}
	for _, item := range page.Items {
		if item.DeletionTimestamp == nil && item.DeletionGracePeriodSeconds == nil {
			out.Namespaces = append(out.Namespaces, cfg.NamespaceRef{Name: item.Name, UID: string(item.UID)})
		}
	}
	return out, nil
}
func (c *PermissionClient) DiscoverCapacityWorkloads(ctx context.Context, namespace cfg.NamespaceRef, kind, continuation string) (app.CapacityWorkloadPage, error) {
	path, ok := capacityWorkloadPath(namespace.Name, kind)
	if !ok || !namespaceRefValid(namespace) {
		return app.CapacityWorkloadPage{}, cfg.ErrInvalid
	}
	page, e := c.capacityMetadataPage(ctx, path, namespace.Name, continuation)
	if e != nil {
		return app.CapacityWorkloadPage{}, e
	}
	out := app.CapacityWorkloadPage{ResourceVersion: page.ResourceVersion, Continue: page.Continue}
	for _, item := range page.Items {
		if item.DeletionTimestamp != nil || item.DeletionGracePeriodSeconds != nil || kind == "Pod" && len(item.OwnerReferences) != 0 {
			continue
		}
		out.Workloads = append(out.Workloads, cfg.WorkloadRef{Kind: kind, Name: item.Name, UID: string(item.UID)})
	}
	return out, nil
}
func (c *PermissionClient) capacityWorkloadMetadata(ctx context.Context, ns cfg.NamespaceRef, ref cfg.WorkloadRef) (metav1.PartialObjectMetadata, error) {
	var out metav1.PartialObjectMetadata
	path, ok := capacityWorkloadPath(ns.Name, ref.Kind)
	if !ok || len(validation.IsDNS1123Subdomain(ref.Name)) != 0 || !identity.Text(ref.UID, 64) {
		return out, cfg.ErrInvalid
	}
	b, e := c.api.Get().AbsPath(path+"/"+ref.Name).MaxRetries(0).SetHeader("Accept", capacityMetadataAccept).DoRaw(ctx)
	if e != nil {
		return out, permissionError(ctx, e)
	}
	if permissionJSON(b, permissionPageBytes, 131072) != nil || json.Unmarshal(b, &out) != nil || out.APIVersion != "meta.k8s.io/v1" || out.Kind != "PartialObjectMetadata" || !capacityMetadataValid(out.ObjectMeta, ns.Name) || out.Name != ref.Name || string(out.UID) != ref.UID || ref.Kind == "Pod" && len(out.OwnerReferences) != 0 {
		return metav1.PartialObjectMetadata{}, cfg.ErrChanged
	}
	return out, nil
}
func (c *PermissionClient) ReadCapacityWorkload(ctx context.Context, ns cfg.NamespaceRef, ref cfg.WorkloadRef, keys []string) (app.CapacityWorkloadObservation, error) {
	var out app.CapacityWorkloadObservation
	if c == nil || ctx == nil || ctx.Err() != nil || !namespaceRefValid(ns) || len(keys) < 1 || len(keys) > 256 {
		return out, cfg.ErrInvalid
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if len(validation.IsQualifiedName(k)) != 0 || seen[k] {
			return out, cfg.ErrInvalid
		}
		seen[k] = true
	}
	start := c.now()
	until := start.Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	first, e := c.namespace(live, ns)
	if e != nil || first.Deleting {
		return out, cfg.ErrChanged
	}
	workload, e := c.capacityWorkloadMetadata(live, ns, ref)
	if e != nil {
		return out, e
	}
	last, e := c.namespace(live, ns)
	if e != nil || last.Deleting {
		return out, cfg.ErrChanged
	}
	labels := map[string]string{}
	for _, k := range keys {
		a, foundA := first.Labels[k]
		b, foundB := last.Labels[k]
		if foundA != foundB || a != b {
			return out, cfg.ErrChanged
		}
		if foundB {
			if len(validation.IsValidLabelValue(b)) != 0 {
				return out, cfg.ErrUnavailable
			}
			labels[k] = b
		}
	}
	final, e := c.capacityWorkloadMetadata(live, ns, ref)
	if e != nil {
		return out, e
	}
	if workload.Generation != final.Generation {
		return out, cfg.ErrChanged
	}
	// Status-only updates may change RV without changing the permanent account.
	// A directly selected Pod must remain unowned in both exact current reads.
	out = app.CapacityWorkloadObservation{Namespace: cfg.NamespaceMetadata{ClusterID: c.clusterID, Namespace: ns, ResourceVersion: last.RV, Labels: labels, ObservedAt: start, FreshUntil: until}, Workload: ref, WorkloadResourceVersion: final.ResourceVersion, ObservedAt: start, FreshUntil: until}
	if live.Err() != nil || !out.Valid(c.now()) {
		return app.CapacityWorkloadObservation{}, cfg.ErrUnavailable
	}
	return out, nil
}
