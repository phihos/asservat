package capacity

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Bounds of one joined cluster's capacity observation (ADR-330).
const (
	RemoteCapacityNamespaces = 512
	RemoteCapacityWorkloads  = 4096
)

// RemoteCapacity is the latest capacity observation a workload cluster
// joined with mode=cluster delivered through its connector (ADR-330): the
// namespaces carrying a capacity key, with only those labels, and their
// capacity workloads. The hub sets ClusterID from the connector's
// authenticated cluster credential and ObservedAt from its own clock when it
// admitted the delivering conversation, before the connector's reads.
type RemoteCapacity struct {
	ClusterID  string
	ObservedAt time.Time
	Namespaces []RemoteCapacityNamespace
}

type RemoteCapacityNamespace struct {
	Namespace       cfg.NamespaceRef
	ResourceVersion string
	Labels          map[string]string
	Workloads       []RemoteCapacityWorkload
}

type RemoteCapacityWorkload struct {
	Workload        cfg.WorkloadRef
	ResourceVersion string
}

// Valid checks identities, uniqueness and the per-cluster bounds.
func (r RemoteCapacity) Valid() bool {
	if !authorization.UUID(r.ClusterID) || r.ObservedAt.IsZero() || len(r.Namespaces) > RemoteCapacityNamespaces {
		return false
	}
	names, uids, workloads := map[string]bool{}, map[string]bool{}, 0
	for _, n := range r.Namespaces {
		if !identity.Text(n.Namespace.Name, 63) || !identity.Text(n.Namespace.UID, 64) || !identity.Text(n.ResourceVersion, 128) || names[n.Namespace.Name] || uids[n.Namespace.UID] || len(n.Labels) > 256 {
			return false
		}
		names[n.Namespace.Name], uids[n.Namespace.UID] = true, true
		for k, v := range n.Labels {
			if !identity.Text(k, 253) || len(v) > 63 {
				return false
			}
		}
		workloads += len(n.Workloads)
		seen := map[string]bool{}
		for _, w := range n.Workloads {
			ref := w.Workload
			if ref.Kind != "Deployment" && ref.Kind != "StatefulSet" && ref.Kind != "Pod" || !identity.Text(ref.Name, 253) || !identity.Text(ref.UID, 64) || !identity.Text(w.ResourceVersion, 128) || seen[ref.UID] || seen[ref.Kind+"/"+ref.Name] {
				return false
			}
			seen[ref.UID], seen[ref.Kind+"/"+ref.Name] = true, true
		}
	}
	return workloads <= RemoteCapacityWorkloads
}

// RemoteCapacityStore reads a cluster's latest stored observation.
type RemoteCapacityStore interface {
	RemoteCapacity(context.Context, string) (RemoteCapacity, error)
}

// RemoteCapacityReader serves the capacity reconciler's reads of one joined
// cluster from its latest delivered observation (ADR-330). The connector
// delivers on change, so the latest delivery stays the cluster's current
// state until a newer one replaces it; each read is current for
// CapacitySourceInterval from the read. Connector liveness is a health
// signal, not capacity authority (as ADR-329 (c) for AccessBindings). Its
// namespace guard is the cluster's write-once regional qualification pin:
// the connector delivers only namespaces carrying the pin's keys.
type RemoteCapacityReader struct {
	Store RemoteCapacityStore
	Pin   CapacityNamespaceQualification
	Now   func() time.Time
}

var (
	_ CapacityWorkloadReader            = RemoteCapacityReader{}
	_ CapacityNamespaceProtectionReader = RemoteCapacityReader{}
	_ CapacityGuardedWorkloadReader     = RemoteCapacityReader{}
)

// current is the latest observation, observed now.
func (r RemoteCapacityReader) current(ctx context.Context) (RemoteCapacity, time.Time, error) {
	if r.Store == nil || r.Now == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(r.Pin.ClusterID) {
		return RemoteCapacity{}, time.Time{}, cfg.ErrUnavailable
	}
	c, err := r.Store.RemoteCapacity(ctx, r.Pin.ClusterID)
	if err != nil {
		return RemoteCapacity{}, time.Time{}, err
	}
	if c.ClusterID != r.Pin.ClusterID || !c.Valid() {
		return RemoteCapacity{}, time.Time{}, cfg.ErrUnavailable
	}
	c.ObservedAt = r.Now()
	return c, c.ObservedAt.Add(CapacitySourceInterval), nil
}

func (r RemoteCapacityReader) DiscoverCapacityNamespaces(ctx context.Context, continuation string) (CapacityNamespacePage, error) {
	c, _, err := r.current(ctx)
	if err != nil || continuation != "" {
		return CapacityNamespacePage{}, cfg.ErrUnavailable
	}
	out := CapacityNamespacePage{ResourceVersion: c.ObservedAt.UTC().Format(time.RFC3339Nano)}
	for _, n := range c.Namespaces {
		out.Namespaces = append(out.Namespaces, n.Namespace)
	}
	return out, nil
}

func (r RemoteCapacityReader) DiscoverCapacityWorkloads(ctx context.Context, namespace cfg.NamespaceRef, kind, continuation string) (CapacityWorkloadPage, error) {
	c, _, err := r.current(ctx)
	if err != nil || continuation != "" {
		return CapacityWorkloadPage{}, cfg.ErrUnavailable
	}
	out := CapacityWorkloadPage{ResourceVersion: c.ObservedAt.UTC().Format(time.RFC3339Nano)}
	for _, n := range c.Namespaces {
		if n.Namespace != namespace {
			continue
		}
		for _, w := range n.Workloads {
			if w.Workload.Kind == kind {
				out.Workloads = append(out.Workloads, w.Workload)
			}
		}
	}
	return out, nil
}

func (r RemoteCapacityReader) ReadCapacityWorkload(ctx context.Context, namespace cfg.NamespaceRef, ref cfg.WorkloadRef, keys []string) (CapacityWorkloadObservation, error) {
	c, until, err := r.current(ctx)
	if err != nil {
		return CapacityWorkloadObservation{}, err
	}
	return r.workload(c, until, namespace, ref, keys)
}

func (r RemoteCapacityReader) workload(c RemoteCapacity, until time.Time, namespace cfg.NamespaceRef, ref cfg.WorkloadRef, keys []string) (CapacityWorkloadObservation, error) {
	if !slices.Equal(keys, r.Pin.Keys) {
		return CapacityWorkloadObservation{}, cfg.ErrUnavailable
	}
	for _, n := range c.Namespaces {
		if n.Namespace != namespace {
			continue
		}
		for _, w := range n.Workloads {
			if w.Workload != ref {
				continue
			}
			labels := map[string]string{}
			for _, k := range keys {
				if v, ok := n.Labels[k]; ok {
					labels[k] = v
				}
			}
			out := CapacityWorkloadObservation{Namespace: cfg.NamespaceMetadata{ClusterID: c.ClusterID, Namespace: namespace, ResourceVersion: n.ResourceVersion, Labels: labels, ObservedAt: c.ObservedAt, FreshUntil: until},
				Workload: ref, WorkloadResourceVersion: w.ResourceVersion, ObservedAt: c.ObservedAt, FreshUntil: until}
			if !out.Valid(r.Now()) {
				return CapacityWorkloadObservation{}, cfg.ErrUnavailable
			}
			return out, nil
		}
	}
	return CapacityWorkloadObservation{}, cfg.ErrChanged
}

// CapacityNamespaceProtection is the cluster's qualification pin, current
// while its latest observation is.
func (r RemoteCapacityReader) CapacityNamespaceProtection(ctx context.Context) (CapacityNamespaceProtection, error) {
	c, until, err := r.current(ctx)
	if err != nil {
		return CapacityNamespaceProtection{}, err
	}
	return r.guard(c, until)
}

func (r RemoteCapacityReader) guard(c RemoteCapacity, until time.Time) (CapacityNamespaceProtection, error) {
	out := CapacityNamespaceProtection{ClusterID: c.ClusterID, Digest: r.Pin.Digest, Keys: slices.Clone(r.Pin.Keys), ObservedAt: c.ObservedAt, FreshUntil: until}
	if !out.Valid(r.Now()) {
		return CapacityNamespaceProtection{}, cfg.ErrUnavailable
	}
	return out, nil
}

// ReadCapacityGuardedWorkload answers the guard and the workload from one
// observation.
func (r RemoteCapacityReader) ReadCapacityGuardedWorkload(ctx context.Context, namespace cfg.NamespaceRef, ref cfg.WorkloadRef, keys []string) (CapacityNamespaceProtection, CapacityWorkloadObservation, error) {
	c, until, err := r.current(ctx)
	if err != nil {
		return CapacityNamespaceProtection{}, CapacityWorkloadObservation{}, err
	}
	guard, err := r.guard(c, until)
	if err != nil {
		return CapacityNamespaceProtection{}, CapacityWorkloadObservation{}, err
	}
	workload, err := r.workload(c, until, namespace, ref, keys)
	return guard, workload, err
}
