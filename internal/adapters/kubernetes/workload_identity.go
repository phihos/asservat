package kubernetes

import (
	"context"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ResolveWorkloadIdentity reads only the named namespace/workload. An empty
// Deployment or StatefulSet can therefore discover retained recording sources
// without selecting a replacement Pod or inventing live Pod provenance.
func (c *PodTargets) ResolveWorkloadIdentity(ctx context.Context, r value.WorkloadRequest) (value.WorkloadIdentityResolution, error) {
	var out value.WorkloadIdentityResolution
	if c == nil || c.client == nil || ctx == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	if !r.Valid() || r.ClusterID != c.client.clusterID || len(validation.IsDNS1123Label(r.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(r.Name)) != 0 {
		return out, value.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.namedNamespace(call, r.Namespace)
	if err != nil {
		return out, err
	}
	out.Reference, out.ClusterID, out.Namespace = r, r.ClusterID, ns
	if r.Kind == "Pod" {
		pod, e := c.object(call, "/api/v1/namespaces/"+r.Namespace+"/pods/"+r.Name, "Pod", r.Namespace, r.Name, "")
		if e != nil {
			return value.WorkloadIdentityResolution{}, e
		}
		out.Workload, err = c.podWorkload(call, ns.Name, pod)
	} else {
		plural := "deployments"
		if r.Kind == "StatefulSet" {
			plural = "statefulsets"
		}
		var root targetObject
		root, err = c.object(call, "/apis/apps/v1/namespaces/"+r.Namespace+"/"+plural+"/"+r.Name, r.Kind, r.Namespace, r.Name, "")
		if err == nil {
			out.Workload = cfg.WorkloadRef{Kind: r.Kind, Name: root.ref.Name, UID: root.ref.UID}
		}
	}
	if err != nil {
		return value.WorkloadIdentityResolution{}, err
	}
	// Metadata retains its first-read five-second interval (ADR-260),
	// independently of the completed transport exchange.
	out.ObservedAt, out.FreshUntil = start, start.Add(5*time.Second)
	if c.client.current(call, start, 5*time.Second) != nil || !out.Valid(c.client.now()) {
		return value.WorkloadIdentityResolution{}, value.ErrUnavailable
	}
	return out, nil
}
