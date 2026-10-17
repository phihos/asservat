package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"k8s.io/apimachinery/pkg/util/resourceversion"
)

var _ app.RetentionSourceReader = (*RetentionSources)(nil)

func (s *RetentionSources) ObserveRetention(ctx context.Context, o app.RetentionObservation) error {
	f, p := o.Fence, o.Protection
	if !f.Valid() || f.RootID != s.root || f.Sequence < 1 || p.SourceClusterID != f.Source.ClusterID || p.ControlNamespaceUID != f.Source.ControlNamespaceUID || p.Digest != f.Source.ProtectionDigest || o.List.Snapshot.SourceClusterID != f.Source.ClusterID || o.List.Snapshot.ControlNamespaceUID != f.Source.ControlNamespaceUID || o.List.Snapshot.Hub != f.Source.Hub {
		return value.ErrInvalid
	}
	behind := false
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		behind = false
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		row, err := lockRetentionSource(ctx, q, s.root, f.Source)
		if err != nil {
			return err
		}
		now, err := liveRetentionSource(ctx, q, row, f)
		if err != nil {
			return err
		}
		if !identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) {
			return value.ErrUnavailable
		}
		if _, err = app.NewRetentionJournal(o.List, now); err != nil {
			return value.ErrInvalid
		}
		recordCursor := func() error {
			return q.RecordRetentionListCursor(ctx, custodydb.RecordRetentionListCursorParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, ListCursor: o.List.ResourceVersion})
		}
		invalidate := func() error {
			// This is a committed restriction, not a failed transaction: once a
			// complete LIST proves a changed policy, the previous observation
			// must stop serving even if its original deadline has not expired.
			behind = true
			if err := recordCursor(); err != nil {
				return err
			}
			return q.InvalidateRetentionObservation(ctx, custodydb.InvalidateRetentionObservationParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid})
		}
		// Our qualified Kubernetes 1.35+ CRD profile permits same-resource
		// ordering. Matching final objects alone misses a policy added and then
		// deleted between LISTs. Process history through the LIST watermark first.
		order, err := resourceversion.CompareResourceVersion(row.WatchCursor, o.List.ResourceVersion)
		if err != nil {
			return value.ErrInvalid
		}
		if row.ListCursor != "" {
			newer, err := resourceversion.CompareResourceVersion(o.List.ResourceVersion, row.ListCursor)
			if err != nil {
				return value.ErrInvalid
			}
			if newer < 0 {
				return value.ErrRetentionObservationObsolete
			}
		}
		checkpoint, err := currentRetentionCheckpoint(ctx, q, row)
		if err != nil {
			return err
		}
		if checkpoint == nil || checkpoint.Transition.Fence.Source != f.Source {
			return value.ErrChanged
		}
		journal, err := app.ResumeRetentionJournal(checkpoint.Transition.List)
		if err != nil {
			return err
		}
		if err = journal.Confirm(o.List, now); err != nil {
			return invalidate()
		}
		if order < 0 {
			// Same final objects do not prove intervening history, so do not
			// renew availability yet. They also do not contradict the previously
			// accepted finite observation. Preserve only its ORIGINAL deadline.
			behind = true
			return nil
		}
		observed := identity.Earlier(o.List.Snapshot.ObservedAt, p.ObservedAt).UTC().Truncate(time.Microsecond)
		until := identity.Earlier(o.List.Snapshot.FreshUntil, p.FreshUntil)
		until = identity.Earlier(until, f.LeaseUntil).UTC().Truncate(time.Microsecond)
		if !identity.Fresh(observed, until, now, 5*time.Second) {
			return value.ErrUnavailable
		}
		// Out-of-order observation replies cannot extend an older observation.
		if row.ObservedAt.Valid && (observed.Before(row.ObservedAt.Time) || (observed.Equal(row.ObservedAt.Time) && until.After(row.FreshUntil.Time))) {
			return value.ErrRetentionObservationObsolete
		}
		if err = recordCursor(); err != nil {
			return err
		}
		if err = q.ObserveRetentionSource(ctx, custodydb.ObserveRetentionSourceParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, ObservedAt: ts(observed), FreshUntil: ts(until)}); err != nil {
			return err
		}
		after, err := liveRetentionSource(ctx, q, row, f)
		if err != nil {
			return err
		}
		if !identity.Fresh(observed, until, after, 5*time.Second) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return permissionError(err)
	}
	if behind {
		return value.ErrRetentionHistoryBehind
	}
	return nil
}

func (s *RetentionSources) AcceptedRetentionSource(ctx context.Context, root string, ref privacy.PolicySourceRef) (privacy.AcceptedSource, error) {
	var out privacy.AcceptedSource
	if root != s.root || !app.ValidRetentionSource(ref) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		var err error
		out, err = acceptedRetentionSource(ctx, q, root, ref)
		return err
	})
	if err != nil {
		return privacy.AcceptedSource{}, permissionError(err)
	}
	return out, nil
}

// Caller owns the surrounding transaction. Every source uses root -> source
// locks, permitting final operation fences to share this exact readiness check.
func acceptedRetentionSource(ctx context.Context, q *custodydb.Queries, root string, ref privacy.PolicySourceRef) (privacy.AcceptedSource, error) {
	var out privacy.AcceptedSource
	if _, err := q.SharePermissionStream(ctx, id(root)); err != nil {
		return out, err
	}
	row, err := q.ShareRetentionSource(ctx, custodydb.ShareRetentionSourceParams{RootID: id(root), ClusterID: id(ref.ClusterID), NamespaceUid: ref.ControlNamespaceUID})
	if err != nil {
		return out, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	f := retentionFence(row)
	if f.Source != ref || row.RecoveryBlocked || row.Suspended || row.Sequence < 1 || !row.ObservedSequence.Valid || row.ObservedSequence.Int64 != row.Sequence || !now.Time.Before(row.LeaseUntil.Time) || !identity.Fresh(row.ObservedAt.Time, row.FreshUntil.Time, now.Time, 5*time.Second) {
		return out, value.ErrUnavailable
	}
	complete, err := q.RetentionSourceCaughtUp(ctx, custodydb.RetentionSourceCaughtUpParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid})
	if err != nil {
		return out, err
	}
	if !complete.Valid || !complete.Bool {
		return out, value.ErrUnavailable
	}
	current, err := q.ReadCurrentRetentionCheckpoint(ctx, custodydb.ReadCurrentRetentionCheckpointParams{RootID: row.RootID, ClusterID: row.ClusterID, NamespaceUid: row.NamespaceUid, Sequence: row.Sequence})
	if err != nil {
		return out, err
	}
	checkpoint, err := decodeRetentionCheckpoint(current)
	if err != nil {
		return out, err
	}
	var receipt audit.Receipt
	if !checkpoint.Audited || checkpoint.Transition.Fence.Source != ref || json.Unmarshal(current.AuditReceipt, &receipt) != nil || !receipt.ValidRetentionAcceptance(root, checkpoint.Record.ID) {
		return out, value.ErrUnavailable
	}
	snapshot := checkpoint.Transition.List.Snapshot
	if ref.Hub {
		baselines := 0
		for _, p := range snapshot.Policies {
			if p.Policy.Baseline {
				baselines++
			}
		}
		if baselines != 1 {
			return out, value.ErrUnavailable
		}
	}
	snapshot.ObservedAt = row.ObservedAt.Time
	snapshot.FreshUntil = identity.Earlier(row.FreshUntil.Time, row.LeaseUntil.Time)
	out = privacy.AcceptedSource{RootID: root, Epoch: uid(row.Epoch), Snapshot: snapshot, Acceptance: identity.Revision{UID: checkpoint.Record.ID, Generation: checkpoint.Record.Sequence}, ProtectionDigest: ref.ProtectionDigest, Ready: true, ObservedAt: snapshot.ObservedAt, FreshUntil: snapshot.FreshUntil}
	copy(out.Acceptance.Digest[:], digest(checkpoint.Record))
	after, err := q.CurrentTime(ctx)
	if err != nil {
		return out, err
	}
	if !out.Valid(after.Time) {
		return out, value.ErrUnavailable
	}
	return out, nil
}
