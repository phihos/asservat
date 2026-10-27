package fleet

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

type ClusterObservationPurpose string

const (
	ObserveCapacityNamespaceGuard ClusterObservationPurpose = "capacity-namespace-guard"
	ObserveCapacityNamespaces     ClusterObservationPurpose = "capacity-namespace-candidates"
	ObserveCapacityWorkloads      ClusterObservationPurpose = "capacity-workload-candidates"
	ObserveCapacityWorkload       ClusterObservationPurpose = "capacity-workload"
	// ObserveCapacityGuardedWorkload observes the namespace guard and then
	// the workload under the request's keys, which must be the guard's
	// (ADR-197): two observations do not fit one five-second window.
	ObserveCapacityGuardedWorkload ClusterObservationPurpose = "capacity-guarded-workload"
	// ObservePermissionNamespaces pages the connector's continuous namespace
	// journal of the requested label and annotation keys (ADR-247): each
	// namespace carrying a key, its key values as digests and a version that
	// changes only when an observed key value changes.
	ObservePermissionNamespaces ClusterObservationPurpose = "permission-namespace-metadata"
	// ObservePermissionWorkloads pages the connector's workload journal of
	// one selection (Selector, Keys as labels, AnnotationKeys), and
	// ObservePermissionWorkloadGuard proves its workload metadata guard
	// (ADR-247).
	ObservePermissionWorkloads      ClusterObservationPurpose = "permission-workload-metadata"
	ObservePermissionWorkloadGuard  ClusterObservationPurpose = "permission-workload-guard"
	ClusterObservationMaximumKeys                             = 256
	ClusterObservationMaximumItems                            = 64
	ClusterObservationMaximumCursor                           = 8192
)

// ClusterObservationRequest is a closed read selection, never an authority
// grant. Only an admitted transport can associate it with an installed caller
// and exact local producer. The original interval survives all relay hops.
type ClusterObservationRequest struct {
	ID, Challenge, RootID, ClusterID string
	Purpose                          ClusterObservationPurpose
	RequestedAt, NotAfter            time.Time
	Namespace                        cfg.NamespaceRef
	Workload                         cfg.WorkloadRef
	Kind                             string
	Keys                             []string
	// AnnotationKeys are the observed annotation keys of a permission
	// namespace observation; Keys are its label keys.
	AnnotationKeys []string `json:",omitempty"`
	// Selector is a permission workload observation's label selector.
	Selector map[string]string `json:",omitempty"`
	Continue string
}

// Restrict returns an independent result whose every usable child interval is
// capped by the relay/caller interval. This never substitutes receipt time for
// the producer's original observation, or extends a child during conversion to
// an existing application port. Validation against the original request remains
// mandatory after restriction.
func (v ClusterObservationResult) Restrict(notBefore, notAfter time.Time) ClusterObservationResult {
	if v.Interval.ObservedAt.Before(notBefore) {
		v.Interval.ObservedAt = notBefore
	}
	v.Interval.FreshUntil = identity.Earlier(v.Interval.FreshUntil, notAfter)
	end := v.Interval.FreshUntil
	if v.Guard != nil {
		g := *v.Guard
		g.Keys, g.AnnotationKeys = slices.Clone(g.Keys), slices.Clone(g.AnnotationKeys)
		g.Interval.FreshUntil = identity.Earlier(g.Interval.FreshUntil, end)
		v.Guard = &g
	}
	if v.Namespaces != nil {
		p := *v.Namespaces
		p.Items = slices.Clone(p.Items)
		v.Namespaces = &p
	}
	if v.PermissionNamespaces != nil {
		p := *v.PermissionNamespaces
		p.Items = slices.Clone(p.Items)
		v.PermissionNamespaces = &p
	}
	if v.PermissionWorkloads != nil {
		p := *v.PermissionWorkloads
		p.Items = slices.Clone(p.Items)
		v.PermissionWorkloads = &p
	}
	if v.Workloads != nil {
		p := *v.Workloads
		p.Items = slices.Clone(p.Items)
		v.Workloads = &p
	}
	if v.Workload != nil {
		w := *v.Workload
		if w.Labels != nil {
			w.Labels = make(map[string]string, len(v.Workload.Labels))
			for k, label := range v.Workload.Labels {
				w.Labels[k] = label
			}
		}
		w.NamespaceInterval.FreshUntil = identity.Earlier(w.NamespaceInterval.FreshUntil, end)
		w.Interval.FreshUntil = identity.Earlier(w.Interval.FreshUntil, end)
		v.Workload = &w
	}
	return v
}

func observationNamespace(v cfg.NamespaceRef) bool {
	return identity.Text(v.Name, 63) && identity.Text(v.UID, 64)
}
func observationKind(v string) bool {
	return v == "Deployment" || v == "StatefulSet" || v == "Pod"
}
func observationWorkload(v cfg.WorkloadRef) bool {
	return observationKind(v.Kind) && identity.Text(v.Name, 253) && identity.Text(v.UID, 64)
}
func observationCursor(v string) bool {
	return v == "" || identity.Text(v, ClusterObservationMaximumCursor)
}
func observationKeys(keys []string) bool {
	if len(keys) == 0 || len(keys) > ClusterObservationMaximumKeys {
		return false
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if !identity.Text(key, 253) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func (r ClusterObservationRequest) Valid(now time.Time) bool {
	if !authorization.UUID(r.ID) || !authorization.UUID(r.Challenge) || !authorization.UUID(r.RootID) || !authorization.UUID(r.ClusterID) || !identity.Fresh(r.RequestedAt, r.NotAfter, now, 5*time.Second) || !observationCursor(r.Continue) {
		return false
	}
	emptyNamespace, emptyWorkload := r.Namespace == (cfg.NamespaceRef{}), r.Workload == (cfg.WorkloadRef{})
	switch r.Purpose {
	case ObserveCapacityNamespaceGuard, ObservePermissionWorkloadGuard:
		return emptyNamespace && emptyWorkload && r.Kind == "" && len(r.Keys) == 0 && len(r.AnnotationKeys) == 0 && len(r.Selector) == 0 && r.Continue == ""
	case ObservePermissionWorkloads:
		return emptyNamespace && emptyWorkload && r.Kind == "" && cfg.WorkloadSelection{Selector: r.Selector, Keys: cfg.NamespaceKeys{Labels: r.Keys, Annotations: r.AnnotationKeys}}.Valid()
	case ObserveCapacityNamespaces:
		return emptyNamespace && emptyWorkload && r.Kind == "" && len(r.Keys) == 0
	case ObserveCapacityWorkloads:
		return observationNamespace(r.Namespace) && emptyWorkload && observationKind(r.Kind) && len(r.Keys) == 0
	case ObserveCapacityWorkload, ObserveCapacityGuardedWorkload:
		return observationNamespace(r.Namespace) && observationWorkload(r.Workload) && r.Kind == "" && observationKeys(r.Keys) && r.Continue == "" && len(r.AnnotationKeys) == 0
	case ObservePermissionNamespaces:
		keys := cfg.NamespaceKeys{Labels: r.Keys, Annotations: r.AnnotationKeys}
		return emptyNamespace && emptyWorkload && r.Kind == "" && keys.Valid() && len(r.Keys)+len(r.AnnotationKeys) > 0
	}
	return false
}
func (r ClusterObservationRequest) Clone() ClusterObservationRequest {
	r.Keys = slices.Clone(r.Keys)
	r.AnnotationKeys = slices.Clone(r.AnnotationKeys)
	if r.Selector != nil {
		selector := make(map[string]string, len(r.Selector))
		for k, v := range r.Selector {
			selector[k] = v
		}
		r.Selector = selector
	}
	return r
}

type ClusterObservationInterval struct{ ObservedAt, FreshUntil time.Time }

func (i ClusterObservationInterval) Valid(now time.Time) bool {
	return identity.Fresh(i.ObservedAt, i.FreshUntil, now, 5*time.Second)
}

type ClusterNamespaceGuardObservation struct {
	Digest artifact.Digest
	Keys   []string
	// AnnotationKeys are a workload guard's annotation keys (ADR-247).
	AnnotationKeys []string `json:",omitempty"`
	Interval       ClusterObservationInterval
}

// ClusterPermissionWorkloadPage is one page of a connector workload journal
// at one (Journal, Sequence) state (ADR-247), like
// ClusterPermissionNamespacePage.
type ClusterPermissionWorkloadPage struct {
	Journal    string
	Sequence   int64
	ObservedAt time.Time
	Continue   string
	Items      []cfg.ObservedWorkload
}
type ClusterNamespaceCandidatePage struct {
	ResourceVersion, Continue string
	Items                     []cfg.NamespaceRef
}

// ClusterPermissionNamespacePage is one page of a connector's namespace
// journal at one (Journal, Sequence) state (ADR-247). ObservedAt is the start
// of the journal's latest complete LIST or cleanly ended watch session: the
// age of what it reports. Each item's ResourceVersion is the journal version
// "<journal>:<changes>", unchanged unless an observed key value changed.
type ClusterPermissionNamespacePage struct {
	Journal    string
	Sequence   int64
	ObservedAt time.Time
	Continue   string
	Items      []cfg.ObservedNamespace
}

type ClusterWorkloadCandidatePage struct {
	ResourceVersion, Continue string
	Items                     []cfg.WorkloadRef
}
type ClusterExactWorkloadObservation struct {
	Namespace                cfg.NamespaceRef
	NamespaceResourceVersion string
	Labels                   map[string]string
	NamespaceInterval        ClusterObservationInterval
	Workload                 cfg.WorkloadRef
	WorkloadResourceVersion  string
	Interval                 ClusterObservationInterval
}

// A successful empty candidate page is distinct from an unavailable response.
// Only the exact union member may exist. A result is still not a permit: the
// consumer rechecks the accepted source/permissions/recovery before its effect.
type ClusterObservationResult struct {
	RequestID, Challenge, RootID, ClusterID string
	Purpose                                 ClusterObservationPurpose
	RequestDigest                           artifact.Digest
	Interval                                ClusterObservationInterval
	Guard                                   *ClusterNamespaceGuardObservation
	Namespaces                              *ClusterNamespaceCandidatePage
	Workloads                               *ClusterWorkloadCandidatePage
	Workload                                *ClusterExactWorkloadObservation
	PermissionNamespaces                    *ClusterPermissionNamespacePage `json:",omitempty"`
	PermissionWorkloads                     *ClusterPermissionWorkloadPage  `json:",omitempty"`
}

func (v ClusterObservationResult) Matches(r ClusterObservationRequest, digest artifact.Digest, now time.Time) bool {
	if !r.Valid(now) || digest == (artifact.Digest{}) || v.RequestDigest != digest || v.RequestID != r.ID || v.Challenge != r.Challenge || v.RootID != r.RootID || v.ClusterID != r.ClusterID || v.Purpose != r.Purpose || !v.Interval.Valid(now) || v.Interval.ObservedAt.Before(r.RequestedAt) || v.Interval.FreshUntil.After(r.NotAfter) {
		return false
	}
	members := 0
	for _, present := range []bool{v.Guard != nil, v.Namespaces != nil, v.Workloads != nil, v.Workload != nil, v.PermissionNamespaces != nil, v.PermissionWorkloads != nil} {
		if present {
			members++
		}
	}
	// The guarded workload alone carries two members: its guard and workload.
	if r.Purpose == ObserveCapacityGuardedWorkload {
		if members != 2 || v.Guard == nil || v.Workload == nil {
			return false
		}
	} else if members != 1 {
		return false
	}
	// The envelope is the intersection of the original child observations. It
	// may start later, but must never end after a fact on which it depends.
	within := func(i ClusterObservationInterval) bool {
		return i.Valid(now) && !v.Interval.ObservedAt.Before(i.ObservedAt) && !v.Interval.FreshUntil.After(i.FreshUntil)
	}
	switch r.Purpose {
	case ObserveCapacityNamespaceGuard:
		return v.Guard != nil && v.Guard.Digest != (artifact.Digest{}) && observationKeys(v.Guard.Keys) && len(v.Guard.AnnotationKeys) == 0 && within(v.Guard.Interval)
	case ObservePermissionWorkloadGuard:
		return v.Guard != nil && v.Guard.Digest != (artifact.Digest{}) && cfg.NamespaceKeys{Labels: v.Guard.Keys, Annotations: v.Guard.AnnotationKeys}.Valid() && len(v.Guard.Keys)+len(v.Guard.AnnotationKeys) > 0 && within(v.Guard.Interval)
	case ObservePermissionWorkloads:
		p := v.PermissionWorkloads
		if p == nil || !authorization.UUID(p.Journal) || p.Sequence < 0 || p.ObservedAt.IsZero() || p.ObservedAt.After(v.Interval.FreshUntil) || !observationCursor(p.Continue) || len(p.Items) > ClusterObservationMaximumItems || p.Items == nil {
			return false
		}
		keys := cfg.NamespaceKeys{Labels: r.Keys, Annotations: r.AnnotationKeys}
		for i, item := range p.Items {
			if !item.Valid(keys, true) || !strings.HasPrefix(item.ResourceVersion, p.Journal+":") || i > 0 && p.Items[i-1].UID >= item.UID {
				return false
			}
		}
		return true
	case ObserveCapacityNamespaces:
		p := v.Namespaces
		if p == nil || !identity.Text(p.ResourceVersion, 128) || !observationCursor(p.Continue) || len(p.Items) > ClusterObservationMaximumItems || p.Items == nil {
			return false
		}
		seen := make(map[string]bool, len(p.Items))
		for _, item := range p.Items {
			if !observationNamespace(item) || seen[item.UID] {
				return false
			}
			seen[item.UID] = true
		}
		return true
	case ObservePermissionNamespaces:
		p := v.PermissionNamespaces
		if p == nil || !authorization.UUID(p.Journal) || p.Sequence < 0 || p.ObservedAt.IsZero() || p.ObservedAt.After(v.Interval.FreshUntil) || !observationCursor(p.Continue) || len(p.Items) > ClusterObservationMaximumItems || p.Items == nil {
			return false
		}
		keys := cfg.NamespaceKeys{Labels: r.Keys, Annotations: r.AnnotationKeys}
		for i, item := range p.Items {
			if !item.Valid(keys, true) || !strings.HasPrefix(item.ResourceVersion, p.Journal+":") || i > 0 && p.Items[i-1].UID >= item.UID {
				return false
			}
		}
		return true
	case ObserveCapacityWorkloads:
		p := v.Workloads
		if p == nil || !identity.Text(p.ResourceVersion, 128) || !observationCursor(p.Continue) || len(p.Items) > ClusterObservationMaximumItems || p.Items == nil {
			return false
		}
		seen := make(map[string]bool, len(p.Items))
		for _, item := range p.Items {
			if !observationWorkload(item) || item.Kind != r.Kind || seen[item.UID] {
				return false
			}
			seen[item.UID] = true
		}
		return true
	case ObserveCapacityWorkload, ObserveCapacityGuardedWorkload:
		if r.Purpose == ObserveCapacityGuardedWorkload && (v.Guard.Digest == (artifact.Digest{}) || !slices.Equal(v.Guard.Keys, r.Keys) || !within(v.Guard.Interval)) {
			return false
		}
		w := v.Workload
		if w == nil || w.Namespace != r.Namespace || w.Workload != r.Workload || !identity.Text(w.NamespaceResourceVersion, 128) || !identity.Text(w.WorkloadResourceVersion, 128) || w.Labels == nil || len(w.Labels) > len(r.Keys) || !within(w.NamespaceInterval) || !within(w.Interval) || w.Interval.FreshUntil.After(w.NamespaceInterval.FreshUntil) {
			return false
		}
		for key, label := range w.Labels {
			if !slices.Contains(r.Keys, key) || label != "" && !identity.Text(label, 63) {
				return false
			}
		}
		return true
	}
	return false
}
