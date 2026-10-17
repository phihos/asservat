package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

// One fixed-cluster adapter consumes the concrete authenticated local hop. It
// has no Kubernetes credential, SQL handle, route callback or caller endpoint.
// The enclosing installed worker owns and joins the single shared installed client.
type capacityRemoteObservation struct {
	client            capacityClusterExchange
	rootID, clusterID string
	now               func() time.Time
	// diagnose logs one closed purpose and outcome per change, with its
	// elapsed time, labelled "regional" or "local" (ADR-197); never remote text.
	diagnose string
	mu       sync.Mutex
	last     string
	workload string
}

// regionalOutcome is "ok" or the error's fixed step and closed cause.
func regionalOutcome(err error) string {
	if err == nil {
		return "ok"
	}
	var step interface{ FixedStep() string }
	if errors.As(err, &step) {
		return step.FixedStep() + " (" + regionalCause(err) + ")"
	}
	return regionalCause(err)
}

// reportWorkload logs one regional workload reconciliation outcome per change
// with its elapsed time (ADR-197): which enrollment stage refused, if any.
func (s *capacityRemoteObservation) reportWorkload(err error, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if outcome := regionalOutcome(err); outcome != s.workload {
		s.workload = outcome
		fmt.Fprintf(os.Stderr, "capacity %s workload: %s after %s\n", s.diagnose, outcome, elapsed.Round(10*time.Millisecond))
	}
}

// capacityClusterExchange is the installed v1 local client or, for a
// regional cluster, the v2 holder client (ADR-197).
type capacityClusterExchange interface {
	ObserveCluster(context.Context, fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error)
}

var _ app.CapacityWorkloadReader = (*capacityRemoteObservation)(nil)
var _ app.CapacityNamespaceProtectionReader = (*capacityRemoteObservation)(nil)
var _ app.CapacityGuardedWorkloadReader = (*capacityRemoteObservation)(nil)

func newCapacityRemoteObservation(client capacityClusterExchange, rootID, clusterID string, now func() time.Time) (*capacityRemoteObservation, error) {
	if client == nil || !authorization.UUID(rootID) || !authorization.UUID(clusterID) || now == nil {
		return nil, mounts.ErrUnavailable
	}
	return &capacityRemoteObservation{client: client, rootID: rootID, clusterID: clusterID, now: now}, nil
}

func (s *capacityRemoteObservation) observe(ctx context.Context, r fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	if s == nil || s.client == nil || s.now == nil || ctx == nil || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	started := s.now()
	until := started.Add(app.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	r.ID, r.Challenge = ownerRandomID(), ownerRandomID()
	r.RootID, r.ClusterID = s.rootID, s.clusterID
	r.RequestedAt, r.NotAfter = started, until
	r = r.Clone()
	if !r.Valid(s.now()) {
		return zero, mounts.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	result, err := s.client.ObserveCluster(live, r)
	if err == nil && live.Err() != nil {
		err = live.Err()
	}
	if err == nil {
		result, err = capacityCheckedObservation(r, result, until, s.now())
	}
	if s.diagnose != "" {
		s.mu.Lock()
		if line := string(r.Purpose) + ": " + regionalOutcome(err); line != s.last {
			s.last = line
			fmt.Fprintf(os.Stderr, "capacity %s observation %s after %s\n", s.diagnose, line, s.now().Sub(started).Round(10*time.Millisecond))
		}
		s.mu.Unlock()
	}
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	return result, nil
}

// Validation is repeated at the port conversion boundary so a shorter caller
// end can never disappear while converting a typed transport result. Original
// producer starts remain untouched; expiry cannot select a fresh request.
func capacityCheckedObservation(r fleet.ClusterObservationRequest, v fleet.ClusterObservationResult, until, now time.Time) (fleet.ClusterObservationResult, error) {
	digest, err := clusterobservation.RequestDigest(r)
	if err != nil || !v.Matches(r, digest, now) || !now.Before(until) {
		return fleet.ClusterObservationResult{}, mounts.ErrUnavailable
	}
	v = v.Restrict(r.RequestedAt, until)
	if !v.Matches(r, digest, now) {
		return fleet.ClusterObservationResult{}, mounts.ErrUnavailable
	}
	return v, nil
}

func (s *capacityRemoteObservation) CapacityNamespaceProtection(ctx context.Context) (app.CapacityNamespaceProtection, error) {
	v, err := s.observe(ctx, fleet.ClusterObservationRequest{Purpose: fleet.ObserveCapacityNamespaceGuard})
	if err != nil {
		return app.CapacityNamespaceProtection{}, err
	}
	g := v.Guard
	return app.CapacityNamespaceProtection{ClusterID: s.clusterID, Digest: g.Digest, Keys: slices.Clone(g.Keys), ObservedAt: g.Interval.ObservedAt, FreshUntil: g.Interval.FreshUntil}, nil
}

func (s *capacityRemoteObservation) DiscoverCapacityNamespaces(ctx context.Context, cursor string) (app.CapacityNamespacePage, error) {
	v, err := s.observe(ctx, fleet.ClusterObservationRequest{Purpose: fleet.ObserveCapacityNamespaces, Continue: cursor})
	if err != nil {
		return app.CapacityNamespacePage{}, err
	}
	p := v.Namespaces
	return app.CapacityNamespacePage{ResourceVersion: p.ResourceVersion, Continue: p.Continue, Namespaces: slices.Clone(p.Items)}, nil
}

func (s *capacityRemoteObservation) DiscoverCapacityWorkloads(ctx context.Context, namespace cfg.NamespaceRef, kind, cursor string) (app.CapacityWorkloadPage, error) {
	v, err := s.observe(ctx, fleet.ClusterObservationRequest{Purpose: fleet.ObserveCapacityWorkloads, Namespace: namespace, Kind: kind, Continue: cursor})
	if err != nil {
		return app.CapacityWorkloadPage{}, err
	}
	p := v.Workloads
	return app.CapacityWorkloadPage{ResourceVersion: p.ResourceVersion, Continue: p.Continue, Workloads: slices.Clone(p.Items)}, nil
}

func (s *capacityRemoteObservation) ReadCapacityWorkload(ctx context.Context, namespace cfg.NamespaceRef, workload cfg.WorkloadRef, keys []string) (app.CapacityWorkloadObservation, error) {
	v, err := s.observe(ctx, fleet.ClusterObservationRequest{Purpose: fleet.ObserveCapacityWorkload, Namespace: namespace, Workload: workload, Keys: slices.Clone(keys)})
	if err != nil {
		return app.CapacityWorkloadObservation{}, err
	}
	w := v.Workload
	out := app.CapacityWorkloadObservation{Namespace: cfg.NamespaceMetadata{ClusterID: s.clusterID, Namespace: w.Namespace, ResourceVersion: w.NamespaceResourceVersion, Labels: maps.Clone(w.Labels), ObservedAt: w.NamespaceInterval.ObservedAt, FreshUntil: w.NamespaceInterval.FreshUntil}, Workload: w.Workload, WorkloadResourceVersion: w.WorkloadResourceVersion, ObservedAt: w.Interval.ObservedAt, FreshUntil: w.Interval.FreshUntil}
	if ctx.Err() != nil || !out.Valid(s.now()) {
		return app.CapacityWorkloadObservation{}, mounts.ErrUnavailable
	}
	return out, nil
}

// ReadCapacityGuardedWorkload is ADR-197's single regional observation of
// the guard and then the workload under exactly the pinned keys.
func (s *capacityRemoteObservation) ReadCapacityGuardedWorkload(ctx context.Context, namespace cfg.NamespaceRef, workload cfg.WorkloadRef, keys []string) (app.CapacityNamespaceProtection, app.CapacityWorkloadObservation, error) {
	v, err := s.observe(ctx, fleet.ClusterObservationRequest{Purpose: fleet.ObserveCapacityGuardedWorkload, Namespace: namespace, Workload: workload, Keys: slices.Clone(keys)})
	if err != nil {
		return app.CapacityNamespaceProtection{}, app.CapacityWorkloadObservation{}, err
	}
	g, w := v.Guard, v.Workload
	guard := app.CapacityNamespaceProtection{ClusterID: s.clusterID, Digest: g.Digest, Keys: slices.Clone(g.Keys), ObservedAt: g.Interval.ObservedAt, FreshUntil: g.Interval.FreshUntil}
	out := app.CapacityWorkloadObservation{Namespace: cfg.NamespaceMetadata{ClusterID: s.clusterID, Namespace: w.Namespace, ResourceVersion: w.NamespaceResourceVersion, Labels: maps.Clone(w.Labels), ObservedAt: w.NamespaceInterval.ObservedAt, FreshUntil: w.NamespaceInterval.FreshUntil}, Workload: w.Workload, WorkloadResourceVersion: w.WorkloadResourceVersion, ObservedAt: w.Interval.ObservedAt, FreshUntil: w.Interval.FreshUntil}
	if ctx.Err() != nil || !guard.Valid(s.now()) || !out.Valid(s.now()) {
		return app.CapacityNamespaceProtection{}, app.CapacityWorkloadObservation{}, mounts.ErrUnavailable
	}
	return guard, out, nil
}
