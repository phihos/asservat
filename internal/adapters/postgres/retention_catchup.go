package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	config "asservat.local/asservat/internal/application/configuration"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
)

var _ app.RetentionCatchup = (*Retention)(nil)

// ReconcileRetentionPage performs no remote I/O and accepts no caller-selected
// evidence IDs or completion claims. Separate SQL credentials own this facet.
// Only the oldest unfinished source checkpoint can advance; later relaxation
// cannot overtake an earlier shortening. Each finite page commits atomically.
func (s *Retention) ReconcileRetentionPage(ctx context.Context, source value.PolicySourceRef, limit int) (value.RetentionCatchupPage, error) {
	var out value.RetentionCatchupPage
	if !config.ValidRetentionSource(source) || limit < 1 || limit > 16 {
		return out, artifact.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.RetentionCatchupPage{} // a definitely aborted retry keeps no counters
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		current, err := lockRetentionSource(ctx, q, s.root, source)
		if err != nil {
			return err
		}
		if current.RecoveryBlocked || retentionFence(current).Source != source {
			return app.ErrUnavailable
		}
		job, err := q.LockNextRetentionCatchup(ctx, custodydb.LockNextRetentionCatchupParams{RootID: id(s.root), ClusterID: id(source.ClusterID), NamespaceUid: source.ControlNamespaceUID})
		if errors.Is(err, pgx.ErrNoRows) {
			out.Idle = true
			out.Sequence = current.Sequence
			return nil
		}
		if err != nil {
			return err
		}
		row, err := q.ReadRetentionCheckpoint(ctx, custodydb.ReadRetentionCheckpointParams{ID: job.CheckpointID, RootID: id(s.root)})
		if err != nil {
			return err
		}
		checkpoint, err := decodeRetentionCheckpoint(row)
		if err != nil {
			return err
		}
		if checkpoint.Transition.Fence.Source != source || checkpoint.Record.Sequence > current.Sequence {
			return app.ErrConflict
		}
		rows, err := q.ListRetentionCatchupContexts(ctx, custodydb.ListRetentionCatchupContextsParams{RootID: id(s.root), CreatedAt: row.CreatedAt, AfterAttempt: job.AfterAttempt, Hub: source.Hub, ClusterID: id(source.ClusterID), PageLimit: int32(limit + 1)})
		if err != nil {
			return err
		}
		out.CheckpointID = uid(job.CheckpointID)
		out.Sequence = row.Sequence
		out.Complete = len(rows) <= limit
		if len(rows) > limit {
			rows = rows[:limit]
		}
		cursor := job.AfterAttempt
		for _, candidate := range rows {
			hint, err := q.ReadAttempt(ctx, candidate.ID)
			if err != nil {
				return err
			}
			if _, _, err = lockAllocation(ctx, q, uid(hint.AllocationID)); err != nil {
				return err
			}
			a, err := q.LockAttempt(ctx, candidate.ID)
			if err != nil {
				return err
			}
			if a.State == "deleted" {
				cursor = candidate.ID
				out.Visited++
				continue
			}
			r, err := retainedCustodyOrigins(ctx, q, s.root, a)
			if err != nil {
				return err
			}
			policies, err := value.HistoricalSourcePolicies(checkpoint.Transition.List.Snapshot, r)
			if err != nil {
				return err
			}
			deadlines, refs, err := value.ApplyRetainedObligation(r, policies)
			if err != nil {
				return err
			}
			if !deadlines.ExpiresAt.Equal(r.Effective.ExpiresAt) || !deadlines.DeleteBy.Equal(r.Effective.DeleteBy) {
				origins, err := value.MergePolicyOrigins(r.OriginPolicies, refs)
				if err != nil {
					return err
				}
				now, err := q.CurrentTime(ctx)
				if err != nil {
					return err
				}
				decisionID, err := q.RetentionDecisionID(ctx)
				if err != nil {
					return err
				}
				d := value.LifecycleDecision{ID: uid(decisionID), RootID: s.root, Location: r.Registration.Location, Target: r.Input.Target, Sequence: r.Sequence + 1, RegistrationDigest: app.RegistrationDigest(r.Registration), PolicyRevision: identity.Revision{UID: checkpoint.Record.ID, Generation: checkpoint.Record.Sequence, Digest: checkpoint.Record.CheckpointDigest}, Policies: refs, Origins: origins, Previous: r.Effective, Effective: deadlines, ObservedAt: now.Time, ValidUntil: now.Time.Add(5 * time.Second)}
				if err = s.tightenRetention(ctx, q, d); err != nil {
					return err
				}
				if err = q.InsertRetentionCatchupEffect(ctx, custodydb.InsertRetentionCatchupEffectParams{CheckpointID: job.CheckpointID, AttemptID: candidate.ID, DecisionID: decisionID}); err != nil {
					return err
				}
				out.Shortened++
			}
			cursor = candidate.ID
			out.Visited++
		}
		return q.AdvanceRetentionCatchup(ctx, custodydb.AdvanceRetentionCatchupParams{CheckpointID: job.CheckpointID, AfterAttempt: cursor, Visited: int64(out.Visited), Shortened: int64(out.Shortened), Complete: out.Complete})
	})
	if err != nil {
		return value.RetentionCatchupPage{}, err
	}
	return out, nil
}
