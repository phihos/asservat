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
type ClusterObservationMetadata struct {
	client *PermissionClient
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

func NewClusterObservationMetadata(client *PermissionClient, rootID string) (*ClusterObservationMetadata, error) {
	if client == nil || !authorization.UUID(rootID) {
		return nil, cfg.ErrInvalid
	}
	return &ClusterObservationMetadata{client: client, rootID: rootID}, nil
}

func (m *ClusterObservationMetadata) ObserveCluster(ctx context.Context, request fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	if m == nil || m.client == nil || ctx == nil || ctx.Err() != nil || request.RootID != m.rootID || request.ClusterID != m.client.clusterID || !request.Valid(m.client.now()) {
		return zero, cfg.ErrInvalid
	}
	deadline, finite := ctx.Deadline()
	if !finite {
		return zero, cfg.ErrInvalid
	}
	request = request.Clone()
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
