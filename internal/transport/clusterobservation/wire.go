// Package clusterobservation owns the closed local and cross-cluster read
// messages. Its codecs cannot authenticate a producer or authorize an effect.
package clusterobservation

import (
	"encoding/hex"
	"maps"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

func readTime(s string) time.Time {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.UTC().Format(time.RFC3339Nano) != s {
		return time.Time{}
	}
	return t
}
func writeTime(t time.Time) string         { return t.UTC().Format(time.RFC3339Nano) }
func writeDigest(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func intervalWire(i fleet.ClusterObservationInterval) contracts.ClusterObservationInterval {
	return contracts.ClusterObservationInterval{ObservedAt: writeTime(i.ObservedAt), FreshUntil: writeTime(i.FreshUntil)}
}
func namespace(n contracts.ClusterObservationNamespace) cfg.NamespaceRef {
	return cfg.NamespaceRef{Name: n.Name, UID: n.UID}
}
func namespaceWire(n cfg.NamespaceRef) contracts.ClusterObservationNamespace {
	return contracts.ClusterObservationNamespace{Name: n.Name, UID: n.UID}
}
func workload(w contracts.ClusterObservationWorkloadRef) cfg.WorkloadRef {
	return cfg.WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID}
}
func workloadWire(w cfg.WorkloadRef) contracts.ClusterObservationWorkloadRef {
	return contracts.ClusterObservationWorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID}
}

func ParseRequest(w contracts.ClusterObservationRequest, now time.Time) (fleet.ClusterObservationRequest, artifact.Digest, error) {
	r := fleet.ClusterObservationRequest{ID: w.RequestID, Challenge: w.Challenge, RootID: w.RootID, ClusterID: w.ClusterID, Purpose: fleet.ClusterObservationPurpose(w.Purpose), RequestedAt: readTime(w.RequestedAt), NotAfter: readTime(w.NotAfter), Kind: w.Kind, Keys: slices.Clone(w.Keys), AnnotationKeys: slices.Clone(w.AnnotationKeys), Selector: maps.Clone(w.Selector), Continue: w.Continue}
	if w.Namespace != nil {
		r.Namespace = namespace(*w.Namespace)
	}
	if w.Workload != nil {
		r.Workload = workload(*w.Workload)
	}
	if w.Format != contracts.ClusterObservationFormat || !r.Valid(now) || (w.Namespace != nil) != (r.Namespace != (cfg.NamespaceRef{})) || (w.Workload != nil) != (r.Workload != (cfg.WorkloadRef{})) {
		return fleet.ClusterObservationRequest{}, artifact.Digest{}, fleet.ErrInvalid
	}
	d, e := RequestDigest(r)
	return r, d, e
}
func RequestDigest(r fleet.ClusterObservationRequest) (artifact.Digest, error) {
	return app.ClusterObservationRequestDigest(r)
}

func ResultWire(v fleet.ClusterObservationResult) contracts.ClusterObservationResult {
	w := contracts.ClusterObservationResult{Format: contracts.ClusterObservationFormat, RequestID: v.RequestID, Challenge: v.Challenge, RootID: v.RootID, ClusterID: v.ClusterID, Purpose: string(v.Purpose), RequestDigest: writeDigest(v.RequestDigest), Interval: intervalWire(v.Interval)}
	if g := v.Guard; g != nil {
		w.Guard = &contracts.ClusterObservationGuard{Digest: writeDigest(g.Digest), Keys: slices.Clone(g.Keys), AnnotationKeys: slices.Clone(g.AnnotationKeys), Interval: intervalWire(g.Interval)}
	}
	if p := v.Namespaces; p != nil {
		w.Namespaces = &contracts.ClusterObservationNamespacePage{ResourceVersion: p.ResourceVersion, Continue: p.Continue}
		if p.Items != nil {
			w.Namespaces.Items = make([]contracts.ClusterObservationNamespace, len(p.Items))
			for i, x := range p.Items {
				w.Namespaces.Items[i] = namespaceWire(x)
			}
		}
	}
	if p := v.Workloads; p != nil {
		w.Workloads = &contracts.ClusterObservationWorkloadPage{ResourceVersion: p.ResourceVersion, Continue: p.Continue}
		if p.Items != nil {
			w.Workloads.Items = make([]contracts.ClusterObservationWorkloadRef, len(p.Items))
			for i, x := range p.Items {
				w.Workloads.Items[i] = workloadWire(x)
			}
		}
	}
	if p := v.PermissionNamespaces; p != nil {
		w.PermissionNamespaces = &contracts.ClusterObservationPermissionNamespacePage{Journal: p.Journal, Sequence: p.Sequence, ObservedAt: writeTime(p.ObservedAt), Continue: p.Continue}
		if p.Items != nil {
			w.PermissionNamespaces.Items = make([]contracts.ClusterObservationPermissionNamespace, len(p.Items))
			for i, x := range p.Items {
				w.PermissionNamespaces.Items[i] = contracts.ClusterObservationPermissionNamespace{Name: x.Name, UID: x.UID, Version: x.ResourceVersion, Deleting: x.Deleting, Labels: maps.Clone(x.Labels), Annotations: maps.Clone(x.Annotations)}
			}
		}
	}
	if p := v.PermissionWorkloads; p != nil {
		w.PermissionWorkloads = &contracts.ClusterObservationPermissionWorkloadPage{Journal: p.Journal, Sequence: p.Sequence, ObservedAt: writeTime(p.ObservedAt), Continue: p.Continue}
		if p.Items != nil {
			w.PermissionWorkloads.Items = make([]contracts.ClusterObservationPermissionWorkload, len(p.Items))
			for i, x := range p.Items {
				w.PermissionWorkloads.Items[i] = contracts.ClusterObservationPermissionWorkload{Kind: x.Kind, Namespace: namespaceWire(x.Namespace),
					Workload: contracts.ClusterObservationPermissionNamespace{Name: x.Name, UID: x.UID, Version: x.ResourceVersion, Deleting: x.Deleting, Labels: maps.Clone(x.Labels), Annotations: maps.Clone(x.Annotations)}}
			}
		}
	}
	if p := v.Workload; p != nil {
		w.Workload = &contracts.ClusterObservationExactWorkload{Namespace: namespaceWire(p.Namespace), NamespaceResourceVersion: p.NamespaceResourceVersion, Labels: maps.Clone(p.Labels), NamespaceInterval: intervalWire(p.NamespaceInterval), Workload: workloadWire(p.Workload), WorkloadResourceVersion: p.WorkloadResourceVersion, Interval: intervalWire(p.Interval)}
	}
	return w
}
