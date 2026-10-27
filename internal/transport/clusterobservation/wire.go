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
func writeTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func readDigest(s string) artifact.Digest {
	var d artifact.Digest
	b, e := hex.DecodeString(s)
	if e == nil && len(b) == 32 && hex.EncodeToString(b) == s {
		copy(d[:], b)
	}
	return d
}
func writeDigest(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func interval(i contracts.ClusterObservationInterval) fleet.ClusterObservationInterval {
	return fleet.ClusterObservationInterval{ObservedAt: readTime(i.ObservedAt), FreshUntil: readTime(i.FreshUntil)}
}
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

func RequestWire(r fleet.ClusterObservationRequest) contracts.ClusterObservationRequest {
	w := contracts.ClusterObservationRequest{Format: contracts.ClusterObservationFormat, RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: string(r.Purpose), RequestedAt: writeTime(r.RequestedAt), NotAfter: writeTime(r.NotAfter), Kind: r.Kind, Keys: slices.Clone(r.Keys), AnnotationKeys: slices.Clone(r.AnnotationKeys), Selector: maps.Clone(r.Selector), Continue: r.Continue}
	if r.Namespace != (cfg.NamespaceRef{}) {
		n := namespaceWire(r.Namespace)
		w.Namespace = &n
	}
	if r.Workload != (cfg.WorkloadRef{}) {
		v := workloadWire(r.Workload)
		w.Workload = &v
	}
	return w
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
func ParseResult(w contracts.ClusterObservationResult, r fleet.ClusterObservationRequest, d artifact.Digest, now time.Time) (fleet.ClusterObservationResult, error) {
	v := fleet.ClusterObservationResult{RequestID: w.RequestID, Challenge: w.Challenge, RootID: w.RootID, ClusterID: w.ClusterID, Purpose: fleet.ClusterObservationPurpose(w.Purpose), RequestDigest: readDigest(w.RequestDigest), Interval: interval(w.Interval)}
	if g := w.Guard; g != nil {
		v.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: readDigest(g.Digest), Keys: slices.Clone(g.Keys), AnnotationKeys: slices.Clone(g.AnnotationKeys), Interval: interval(g.Interval)}
	}
	if p := w.Namespaces; p != nil {
		v.Namespaces = &fleet.ClusterNamespaceCandidatePage{ResourceVersion: p.ResourceVersion, Continue: p.Continue}
		if p.Items != nil {
			v.Namespaces.Items = make([]cfg.NamespaceRef, len(p.Items))
			for i, x := range p.Items {
				v.Namespaces.Items[i] = namespace(x)
			}
		}
	}
	if p := w.Workloads; p != nil {
		v.Workloads = &fleet.ClusterWorkloadCandidatePage{ResourceVersion: p.ResourceVersion, Continue: p.Continue}
		if p.Items != nil {
			v.Workloads.Items = make([]cfg.WorkloadRef, len(p.Items))
			for i, x := range p.Items {
				v.Workloads.Items[i] = workload(x)
			}
		}
	}
	if p := w.PermissionNamespaces; p != nil {
		v.PermissionNamespaces = &fleet.ClusterPermissionNamespacePage{Journal: p.Journal, Sequence: p.Sequence, ObservedAt: readTime(p.ObservedAt), Continue: p.Continue}
		if p.Items != nil {
			v.PermissionNamespaces.Items = make([]cfg.ObservedNamespace, len(p.Items))
			for i, x := range p.Items {
				v.PermissionNamespaces.Items[i] = cfg.ObservedNamespace{Name: x.Name, UID: x.UID, ResourceVersion: x.Version, Deleting: x.Deleting, Labels: maps.Clone(x.Labels), Annotations: maps.Clone(x.Annotations)}
			}
		}
	}
	if p := w.PermissionWorkloads; p != nil {
		v.PermissionWorkloads = &fleet.ClusterPermissionWorkloadPage{Journal: p.Journal, Sequence: p.Sequence, ObservedAt: readTime(p.ObservedAt), Continue: p.Continue}
		if p.Items != nil {
			v.PermissionWorkloads.Items = make([]cfg.ObservedWorkload, len(p.Items))
			for i, x := range p.Items {
				o := x.Workload
				v.PermissionWorkloads.Items[i] = cfg.ObservedWorkload{Kind: x.Kind, Namespace: namespace(x.Namespace), ObservedNamespace: cfg.ObservedNamespace{Name: o.Name, UID: o.UID, ResourceVersion: o.Version, Deleting: o.Deleting, Labels: maps.Clone(o.Labels), Annotations: maps.Clone(o.Annotations)}}
			}
		}
	}
	if p := w.Workload; p != nil {
		v.Workload = &fleet.ClusterExactWorkloadObservation{Namespace: namespace(p.Namespace), NamespaceResourceVersion: p.NamespaceResourceVersion, Labels: maps.Clone(p.Labels), NamespaceInterval: interval(p.NamespaceInterval), Workload: workload(p.Workload), WorkloadResourceVersion: p.WorkloadResourceVersion, Interval: interval(p.Interval)}
	}
	if w.Format != contracts.ClusterObservationFormat || !v.Matches(r, d, now) {
		return fleet.ClusterObservationResult{}, fleet.ErrUnavailable
	}
	return v, nil
}
