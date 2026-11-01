package capture

import (
	"context"
	"slices"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
)

type SnapshotCancellationTarget struct {
	ClusterID string
	Snapshot  collector.SourceSnapshot
}
type SnapshotCancellationGroup struct {
	ParentCaptureID string
	Targets         []SnapshotCancellationTarget
}

type SnapshotCancellationWork struct {
	Group     *SnapshotCancellationGroup
	Decision  value.Cancellation
	ClusterID string
	Snapshot  *collector.SourceSnapshot
}

// CaptureCancellationLedger must persist the exact idempotency/revision-bound
// request under current requester/workload authority before returning work.
// It fences future starts and never refunds uncertain spend or erases evidence.
type CaptureCancellationLedger interface {
	RequestCaptureCancellation(context.Context, value.CancellationCheck) (SnapshotCancellationWork, error)
}
type CaptureSnapshotCancellationDispatcher interface {
	CancelSourceSnapshot(context.Context, string, collector.SourceSnapshot) error
}

// CaptureCancellation uses the existing request and regional delivery paths.
// Acquisition settings/targets/storage availability cannot block this restrictive
// operation; the SQL owner independently rechecks current cancellation rights.
type CaptureCancellation struct {
	RootID, InstallationID string
	Ledger                 CaptureCancellationLedger
	Dispatcher             CaptureSnapshotCancellationDispatcher
	Recovery               fleetapp.RecoveryReader
	Now                    func() time.Time
}

func (s CaptureCancellation) Cancel(ctx context.Context, current identities.CurrentIdentity, request value.CancellationRequest) (value.Cancellation, error) {
	var zero value.Cancellation
	if ctx == nil || ctx.Err() != nil || current == nil || s.Ledger == nil || s.Dispatcher == nil || s.Recovery == nil || s.Now == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) {
		return zero, value.ErrUnavailable
	}
	if !request.Valid() {
		return zero, value.ErrInvalid
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	call, end := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer end()
	i, err := current.ResolveIdentity(call)
	if err != nil || !i.Valid(s.Now()) || !slices.Contains(i.Scopes, "evidence:capture") {
		return zero, value.ErrDenied
	}
	recovery, err := s.Recovery.RecoveryState(call)
	if err != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != s.InstallationID {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(started.Add(5*time.Second), identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	bounded, cancel := context.WithDeadline(call, until)
	defer cancel()
	check := value.CancellationCheck{RootID: s.RootID, Request: request, Identity: i, Recovery: recovery, CheckedAt: started, ValidUntil: until}
	if !check.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	work, err := s.Ledger.RequestCaptureCancellation(bounded, check)
	if err != nil {
		return zero, err
	}
	decision := work.Decision
	decision.ValidUntil = identity.Earlier(decision.ValidUntil, until)
	if !decision.Valid(s.Now()) || decision.CaptureID != request.CaptureID || bounded.Err() != nil {
		return zero, value.ErrChanged
	}
	if group := work.Group; group != nil {
		if work.Snapshot != nil || group.ParentCaptureID != request.CaptureID || len(group.Targets) > value.MaxRecordingSaveGroupChildren {
			return zero, value.ErrChanged
		}
		seen := map[string]bool{}
		for _, target := range group.Targets {
			x := target.Snapshot
			if !decision.Requested || !authorization.UUID(target.ClusterID) || !x.Valid() || x.CaptureID == request.CaptureID || seen[x.CaptureID] || x.Binding.RootID != s.RootID {
				return zero, value.ErrChanged
			}
			seen[x.CaptureID] = true
		}
		var firstError error
		for _, target := range group.Targets {
			if err := s.Dispatcher.CancelSourceSnapshot(bounded, target.ClusterID, target.Snapshot); err != nil && firstError == nil {
				firstError = err
			}
			if bounded.Err() != nil {
				break
			}
		}
		if firstError != nil {
			return decision, firstError
		}
	}
	if snapshot := work.Snapshot; snapshot != nil {
		if !decision.Requested || !authorization.UUID(work.ClusterID) || !snapshot.Valid() || snapshot.CaptureID != request.CaptureID || snapshot.Binding.RootID != s.RootID {
			return zero, value.ErrChanged
		}
		// Enqueue/unknown delivery never becomes a claim that collection stopped.
		// The persisted request and original snapshot identity survive this reply.
		if err = s.Dispatcher.CancelSourceSnapshot(bounded, work.ClusterID, *snapshot); err != nil {
			return decision, err
		}
	}
	if bounded.Err() != nil || !decision.Valid(s.Now()) || !recovery.Valid(s.Now()) {
		return zero, value.ErrChanged
	}
	return decision, nil
}
