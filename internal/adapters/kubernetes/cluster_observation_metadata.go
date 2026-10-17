package kubernetes

import (
	"context"
	"maps"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ClusterObservationMetadata is the four-purpose regional value reader. Its
// results grant no peer, channel, source-acceptance or capacity authority. The
// admitted operation channel must perform its separate before/after native,
// current SQL and private-key checks around this reader.
//
// Both native clients are retained by the supplied namespace guard; this reader
// creates no client, limiter, credential or per-request source renewal.
type ClusterObservationMetadata struct {
	client *PermissionClient
	guard  *CapacityNamespaceGuard
	rootID string
}

var _ app.ClusterObservationExchange = (*ClusterObservationMetadata)(nil)

func NewClusterObservationMetadata(client *PermissionClient, guard *CapacityNamespaceGuard, rootID string) (*ClusterObservationMetadata, error) {
	if client == nil || guard == nil || guard.guard == nil || guard.guard.observer != client || !authorization.UUID(rootID) {
		return nil, cfg.ErrInvalid
	}
	return &ClusterObservationMetadata{client: client, guard: guard, rootID: rootID}, nil
}

func (m *ClusterObservationMetadata) ObserveCluster(ctx context.Context, request fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	if m == nil || m.client == nil || m.guard == nil || ctx == nil || ctx.Err() != nil || request.RootID != m.rootID || request.ClusterID != m.client.clusterID || !request.Valid(m.client.now()) {
		return zero, cfg.ErrInvalid
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return zero, cfg.ErrInvalid
	}
	request = request.Clone()
	if request.Purpose == fleet.ObserveCapacityWorkload || request.Purpose == fleet.ObserveCapacityGuardedWorkload {
		for _, key := range request.Keys {
			if !slices.Contains(m.guard.keys, key) {
				return zero, cfg.ErrInvalid
			}
		}
	}
	if request.Purpose == fleet.ObserveCapacityWorkloads {
		if _, valid := capacityWorkloadPath(request.Namespace.Name, request.Kind); !valid || !namespaceRefValid(request.Namespace) {
			return zero, cfg.ErrInvalid
		}
	}
	digest, err := app.ClusterObservationRequestDigest(request)
	if err != nil {
		return zero, err
	}
	start := m.client.now()
	until := identity.Earlier(deadline, request.NotAfter)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	current := func() error {
		if call.Err() != nil {
			return call.Err()
		}
		if !identity.Fresh(start, until, m.client.now(), 5*time.Second) || !request.Valid(m.client.now()) {
			return cfg.ErrUnavailable
		}
		return nil
	}
	if err = current(); err != nil {
		return zero, err
	}
	out := fleet.ClusterObservationResult{
		RequestID: request.ID, Challenge: request.Challenge, RootID: request.RootID,
		ClusterID: request.ClusterID, Purpose: request.Purpose, RequestDigest: digest,
		Interval: fleet.ClusterObservationInterval{ObservedAt: start, FreshUntil: until},
	}
	switch request.Purpose {
	case fleet.ObserveCapacityNamespaceGuard:
		guard, err := m.guard.CapacityNamespaceProtection(call)
		if err != nil {
			return zero, err
		}
		if !guard.Valid(m.client.now()) || guard.ClusterID != request.ClusterID {
			return zero, cfg.ErrUnavailable
		}
		out.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: guard.Digest, Keys: slices.Clone(guard.Keys), Interval: fleet.ClusterObservationInterval{ObservedAt: guard.ObservedAt, FreshUntil: guard.FreshUntil}}
		out.Interval.ObservedAt = laterObservationTime(start, guard.ObservedAt)
		out.Interval.FreshUntil = identity.Earlier(until, guard.FreshUntil)
	case fleet.ObserveCapacityNamespaces:
		page, err := m.client.DiscoverCapacityNamespaces(call, request.Continue)
		if err != nil {
			return zero, err
		}
		out.Namespaces = &fleet.ClusterNamespaceCandidatePage{ResourceVersion: page.ResourceVersion, Continue: page.Continue, Items: append([]cfg.NamespaceRef{}, page.Namespaces...)}
	case fleet.ObserveCapacityWorkloads:
		// The underlying one-page LIST addresses a namespace by name. Bind
		// this remote selection to its original UID on both sides of that
		// LIST; candidates still do not authorize a workload effect.
		first, err := m.client.namespace(call, request.Namespace)
		if err != nil {
			return zero, err
		}
		if first.Deleting {
			return zero, cfg.ErrChanged
		}
		if err = current(); err != nil {
			return zero, err
		}
		page, err := m.client.DiscoverCapacityWorkloads(call, request.Namespace, request.Kind, request.Continue)
		if err != nil {
			return zero, err
		}
		if err = current(); err != nil {
			return zero, err
		}
		last, err := m.client.namespace(call, request.Namespace)
		if err != nil {
			return zero, err
		}
		if last.Deleting {
			return zero, cfg.ErrChanged
		}
		out.Workloads = &fleet.ClusterWorkloadCandidatePage{ResourceVersion: page.ResourceVersion, Continue: page.Continue, Items: append([]cfg.WorkloadRef{}, page.Workloads...)}
	case fleet.ObserveCapacityGuardedWorkload:
		// ADR-197: the guard first, then the workload under exactly its keys.
		guard, err := m.guard.CapacityNamespaceProtection(call)
		if err != nil {
			return zero, err
		}
		if !guard.Valid(m.client.now()) || guard.ClusterID != request.ClusterID || !slices.Equal(guard.Keys, request.Keys) {
			return zero, cfg.ErrUnavailable
		}
		if err = current(); err != nil {
			return zero, err
		}
		value, err := m.client.ReadCapacityWorkload(call, request.Namespace, request.Workload, request.Keys)
		if err != nil {
			return zero, err
		}
		if !value.Valid(m.client.now()) || value.Namespace.ClusterID != request.ClusterID {
			return zero, cfg.ErrUnavailable
		}
		out.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: guard.Digest, Keys: slices.Clone(guard.Keys), Interval: fleet.ClusterObservationInterval{ObservedAt: guard.ObservedAt, FreshUntil: guard.FreshUntil}}
		out.Workload = &fleet.ClusterExactWorkloadObservation{
			Namespace: value.Namespace.Namespace, NamespaceResourceVersion: value.Namespace.ResourceVersion,
			Labels:            maps.Clone(value.Namespace.Labels),
			NamespaceInterval: fleet.ClusterObservationInterval{ObservedAt: value.Namespace.ObservedAt, FreshUntil: value.Namespace.FreshUntil},
			Workload:          value.Workload, WorkloadResourceVersion: value.WorkloadResourceVersion,
			Interval: fleet.ClusterObservationInterval{ObservedAt: value.ObservedAt, FreshUntil: value.FreshUntil},
		}
		out.Interval.ObservedAt = laterObservationTime(start, laterObservationTime(guard.ObservedAt, laterObservationTime(value.ObservedAt, value.Namespace.ObservedAt)))
		out.Interval.FreshUntil = identity.Earlier(until, identity.Earlier(guard.FreshUntil, identity.Earlier(value.FreshUntil, value.Namespace.FreshUntil)))
	case fleet.ObserveCapacityWorkload:
		value, err := m.client.ReadCapacityWorkload(call, request.Namespace, request.Workload, request.Keys)
		if err != nil {
			return zero, err
		}
		if !value.Valid(m.client.now()) || value.Namespace.ClusterID != request.ClusterID {
			return zero, cfg.ErrUnavailable
		}
		out.Workload = &fleet.ClusterExactWorkloadObservation{
			Namespace: value.Namespace.Namespace, NamespaceResourceVersion: value.Namespace.ResourceVersion,
			Labels:            maps.Clone(value.Namespace.Labels),
			NamespaceInterval: fleet.ClusterObservationInterval{ObservedAt: value.Namespace.ObservedAt, FreshUntil: value.Namespace.FreshUntil},
			Workload:          value.Workload, WorkloadResourceVersion: value.WorkloadResourceVersion,
			Interval: fleet.ClusterObservationInterval{ObservedAt: value.ObservedAt, FreshUntil: value.FreshUntil},
		}
		out.Interval.ObservedAt = laterObservationTime(start, laterObservationTime(value.ObservedAt, value.Namespace.ObservedAt))
		out.Interval.FreshUntil = identity.Earlier(until, identity.Earlier(value.FreshUntil, value.Namespace.FreshUntil))
	default:
		return zero, cfg.ErrInvalid
	}
	if err = current(); err != nil {
		return zero, err
	}
	if !out.Matches(request, digest, m.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}

func laterObservationTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return b
	}
	return a
}
