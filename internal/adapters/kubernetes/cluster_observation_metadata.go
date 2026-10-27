package kubernetes

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
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
	// namespaces is the connector's continuous namespace journal for
	// permission namespace observations (ADR-247); without it they are
	// unavailable.
	namespaces PermissionNamespaceJournal
	// workloads and workloadGuard answer permission workload observations
	// and their guard proof (ADR-247).
	workloads     PermissionWorkloadJournal
	workloadGuard *WorkloadGuard
}

// PermissionWorkloadJournal is the connector's workload journal service
// (ADR-247), configapp.WorkloadJournalService in composition.
type PermissionWorkloadJournal interface {
	Snapshot(context.Context, cfg.WorkloadSelection) (port.WorkloadJournalSnapshot, error)
}

// WithPermissionWorkloads answers permission workload observations from j
// and their guard proofs from g; either may be nil (then unavailable).
func (m *ClusterObservationMetadata) WithPermissionWorkloads(j PermissionWorkloadJournal, g *WorkloadGuard) *ClusterObservationMetadata {
	out := *m
	out.workloads, out.workloadGuard = j, g
	return &out
}

// journalOffset reads a page cursor "<journal>/<sequence>/<offset>" of the
// same journal state; any other state is a change.
func journalOffset(cursor, journal string, sequence int64, n int) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	parts := strings.Split(cursor, "/")
	if len(parts) != 3 || parts[0] != journal || parts[1] != strconv.FormatInt(sequence, 10) {
		return 0, cfg.ErrChanged
	}
	offset, err := strconv.Atoi(parts[2])
	if err != nil || offset <= 0 || offset > n {
		return 0, cfg.ErrChanged
	}
	return offset, nil
}

// PermissionNamespaceJournal is the connector's continuous namespace journal
// (ADR-247), configapp.NamespaceJournalService in composition.
type PermissionNamespaceJournal interface {
	Snapshot(context.Context, cfg.NamespaceKeys) (port.NamespaceJournalSnapshot, error)
}

// WithPermissionNamespaces answers permission namespace observations from j.
func (m *ClusterObservationMetadata) WithPermissionNamespaces(j PermissionNamespaceJournal) *ClusterObservationMetadata {
	out := *m
	out.namespaces = j
	return &out
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
		// This name-addressed page supplies candidates only. The later exact
		// workload observation independently checks the original namespace UID
		// and protected labels; candidate enumeration does not supply that proof.
		page, err := m.client.DiscoverCapacityWorkloads(call, request.Namespace, request.Kind, request.Continue)
		if err != nil {
			return zero, err
		}
		out.Workloads = &fleet.ClusterWorkloadCandidatePage{ResourceVersion: page.ResourceVersion, Continue: page.Continue, Items: append([]cfg.WorkloadRef{}, page.Workloads...)}
	case fleet.ObserveCapacityGuardedWorkload:
		// ADR-197: the guard first, then the workload under exactly its keys.
		guard, err := m.guard.CapacityNamespaceProtection(call)
		if err != nil {
			return zero, &observationStep{"guard", err}
		}
		if !guard.Valid(m.client.now()) || guard.ClusterID != request.ClusterID || !slices.Equal(guard.Keys, request.Keys) {
			return zero, &observationStep{"guard-keys", cfg.ErrUnavailable}
		}
		if err = current(); err != nil {
			return zero, &observationStep{"current", err}
		}
		value, err := m.client.ReadCapacityWorkload(call, request.Namespace, request.Workload, request.Keys)
		if err != nil {
			return zero, &observationStep{"workload", err}
		}
		if !value.Valid(m.client.now()) || value.Namespace.ClusterID != request.ClusterID {
			return zero, &observationStep{"workload-valid", cfg.ErrUnavailable}
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
	case fleet.ObservePermissionNamespaces:
		if m.namespaces == nil {
			return zero, cfg.ErrUnavailable
		}
		snap, err := m.namespaces.Snapshot(call, cfg.NamespaceKeys{Labels: slices.Clone(request.Keys), Annotations: slices.Clone(request.AnnotationKeys)})
		if err != nil {
			return zero, err
		}
		// A page continues only the same journal state; a change in between
		// restarts the caller's complete read.
		offset, err := journalOffset(request.Continue, snap.Journal, snap.Sequence, len(snap.Namespaces))
		if err != nil {
			return zero, err
		}
		end := min(offset+fleet.ClusterObservationMaximumItems, len(snap.Namespaces))
		page := &fleet.ClusterPermissionNamespacePage{Journal: snap.Journal, Sequence: snap.Sequence, ObservedAt: snap.ObservedAt, Items: append([]cfg.ObservedNamespace{}, snap.Namespaces[offset:end]...)}
		if end < len(snap.Namespaces) {
			page.Continue = snap.Journal + "/" + strconv.FormatInt(snap.Sequence, 10) + "/" + strconv.Itoa(end)
		}
		out.PermissionNamespaces = page
	case fleet.ObservePermissionWorkloads:
		if m.workloads == nil {
			return zero, cfg.ErrUnavailable
		}
		snap, err := m.workloads.Snapshot(call, cfg.WorkloadSelection{Selector: maps.Clone(request.Selector), Keys: cfg.NamespaceKeys{Labels: slices.Clone(request.Keys), Annotations: slices.Clone(request.AnnotationKeys)}})
		if err != nil {
			return zero, err
		}
		offset, err := journalOffset(request.Continue, snap.Journal, snap.Sequence, len(snap.Workloads))
		if err != nil {
			return zero, err
		}
		end := min(offset+fleet.ClusterObservationMaximumItems, len(snap.Workloads))
		page := &fleet.ClusterPermissionWorkloadPage{Journal: snap.Journal, Sequence: snap.Sequence, ObservedAt: snap.ObservedAt, Items: append([]cfg.ObservedWorkload{}, snap.Workloads[offset:end]...)}
		if end < len(snap.Workloads) {
			page.Continue = snap.Journal + "/" + strconv.FormatInt(snap.Sequence, 10) + "/" + strconv.Itoa(end)
		}
		out.PermissionWorkloads = page
	case fleet.ObservePermissionWorkloadGuard:
		if m.workloadGuard == nil {
			return zero, cfg.ErrUnavailable
		}
		proof, err := m.workloadGuard.WorkloadGuardProof(call)
		if err != nil {
			return zero, err
		}
		if proof.ClusterID != request.ClusterID || !proof.Current(m.client.now()) {
			return zero, cfg.ErrUnavailable
		}
		out.Guard = &fleet.ClusterNamespaceGuardObservation{Digest: m.workloadGuard.guard.digest, Keys: slices.Clone(proof.LabelKeys), AnnotationKeys: slices.Clone(proof.AnnotationKeys), Interval: fleet.ClusterObservationInterval{ObservedAt: proof.ObservedAt, FreshUntil: proof.FreshUntil}}
		out.Interval.ObservedAt = laterObservationTime(start, proof.ObservedAt)
		out.Interval.FreshUntil = identity.Earlier(until, proof.FreshUntil)
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

// observationStep names the fixed metadata check that refused, for operator
// diagnostics (FixedStep); it wraps the original error.
type observationStep struct {
	step string
	err  error
}

func (e *observationStep) Error() string { return e.step }
func (e *observationStep) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *observationStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}
