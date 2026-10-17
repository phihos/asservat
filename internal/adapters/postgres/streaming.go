package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	privacyvalue "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// RegisterStreaming atomically charges the four final-copy ceilings and the
// temporary multipart obligation, then inserts the attempt, its copies and its
// journal (ADR-166). Replay of the same plan reports custody only.
func (l *Ledger) RegisterStreaming(ctx context.Context, plan artifact.StreamingPlan) (privacy.Record, error) {
	var result privacy.Record
	if plan.Validate() != nil {
		return result, artifact.ErrInvalid
	}
	plan.Registration = normalized(plan.Registration)
	r := plan.Registration
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		p, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
		if err == nil {
			if !bytes.Equal(row.RequestDigest, digest(r)) {
				return privacy.ErrConflict
			}
			stream, e := q.LockStream(ctx, row.ID)
			if e != nil || !bytes.Equal(stream.PlanDigest, digest(plan)) {
				return privacy.ErrConflict
			}
			result, err = record(ctx, q, row, uid(p.StoreID))
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err = current(ctx, q, p, a, r, r.ExpiresAt); err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		overdue, err := q.Overdue(ctx, custodydb.OverdueParams{AllocationID: a.ID, EffectiveDeleteBy: n})
		if err != nil {
			return err
		}
		if overdue {
			return privacy.ErrCapacity
		}
		temporaryObjects := int64(1 + plan.PartLimit())
		changed, err := q.ChargeStreaming(ctx, custodydb.ChargeStreamingParams{ID: a.ID, ChargedBytes: r.ReservedBytes() + plan.TemporaryBytes(), ChargedObjects: 4 + temporaryObjects})
		if err != nil {
			return err
		}
		if changed != 1 {
			return privacy.ErrCapacity
		}
		if err = q.InsertAttempt(ctx, custodydb.InsertAttemptParams{ID: id(r.Location.AttemptID), ClusterID: id(r.Location.ClusterID), ArtifactID: id(r.Location.ArtifactID), AllocationID: a.ID, RequestDigest: digest(r), PoolRevision: r.PoolRevision, AllocationRevision: r.AllocationRevision, NativeLimit: r.NativeLimit, ReservedBytes: r.ReservedBytes(), AnchorAt: ts(r.AnchorAt), WriteUntil: ts(r.WriteUntil), ExpiresAt: ts(r.ExpiresAt), DeleteBy: ts(r.DeleteBy)}); err != nil {
			return err
		}
		for i, limit := range r.Limits() {
			if err = q.InsertCopy(ctx, custodydb.InsertCopyParams{AttemptID: id(r.Location.AttemptID), Role: int16(i), ByteLimit: limit}); err != nil {
				return err
			}
		}
		state, err := json.Marshal(artifact.StreamingState{})
		if err != nil {
			return err
		}
		if err = q.InsertStream(ctx, custodydb.InsertStreamParams{AttemptID: id(r.Location.AttemptID), WriterEpoch: id(plan.WriterEpoch), PlanDigest: digest(plan), TemporaryBytes: plan.TemporaryBytes(), TemporaryObjects: temporaryObjects, State: state}); err != nil {
			return err
		}
		if err = current(ctx, q, p, a, r, r.ExpiresAt); err != nil {
			return err
		}
		if err = q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: id(r.Location.AttemptID), Phase: "registered"}); err != nil {
			return err
		}
		result = privacy.Record{Registration: r, Effective: privacyvalue.Deadlines{AnchorAt: r.AnchorAt, ExpiresAt: r.ExpiresAt, DeleteBy: r.DeleteBy}, State: artifact.Reserved}
		return nil
	})
	return result, err
}

// AdvanceStreaming applies one journal transition under the allocation,
// attempt and journal locks. Fresh claims require current custody before the
// original WriteUntil; the caller must not start the remote request unless
// fresh is true and this call returned without error. Acknowledgements and the
// release record facts of already performed effects and stay possible later.
func (l *Ledger) AdvanceStreaming(ctx context.Context, plan artifact.StreamingPlan, step artifact.StreamingStep) (artifact.StreamingState, bool, error) {
	var state artifact.StreamingState
	var fresh bool
	if plan.Validate() != nil {
		return state, false, artifact.ErrInvalid
	}
	plan.Registration = normalized(plan.Registration)
	r := plan.Registration
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		state, fresh = artifact.StreamingState{}, false
		p, a, err := lockAllocation(ctx, q, r.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, id(r.Location.AttemptID))
		if err != nil {
			return err
		}
		if !bytes.Equal(row.RequestDigest, digest(r)) || p.StoreID != id(r.StoreID) {
			return privacy.ErrConflict
		}
		stream, err := q.LockStream(ctx, row.ID)
		if err != nil || !bytes.Equal(stream.PlanDigest, digest(plan)) {
			return privacy.ErrConflict
		}
		var old artifact.StreamingState
		d := json.NewDecoder(bytes.NewReader(stream.State))
		d.DisallowUnknownFields()
		if d.Decode(&old) != nil || old.Validate(plan) != nil {
			return privacy.ErrUnavailable
		}
		claim := step.Kind == artifact.StreamClaimCreate || step.Kind == artifact.StreamClaimPart || step.Kind == artifact.StreamClaimComplete
		if claim && (row.State != artifact.Reserved || current(ctx, q, p, a, r, row.EffectiveExpiresAt.Time) != nil) {
			return privacy.ErrExpired
		}
		if step.Kind == artifact.StreamRelease {
			n, e := q.CurrentTime(ctx)
			if e != nil {
				return e
			}
			step.At = n.Time
		}
		next, isFresh, err := old.Advance(plan, step)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(next)
		if err != nil {
			return err
		}
		released := pgtype.Timestamptz{}
		if !next.ReleasedAt.IsZero() {
			released = ts(next.ReleasedAt)
			changed, e := q.ReleaseStreamingTemporary(ctx, custodydb.ReleaseStreamingTemporaryParams{ID: a.ID, ChargedBytes: stream.TemporaryBytes, ChargedObjects: stream.TemporaryObjects})
			if e != nil || changed != 1 {
				return privacy.ErrUnavailable
			}
		}
		changed, err := q.UpdateStream(ctx, custodydb.UpdateStreamParams{AttemptID: row.ID, State: encoded, Revision: stream.Revision, ReleasedAt: released})
		if err != nil || changed != 1 {
			return privacy.ErrUnavailable
		}
		// Claims recheck custody after every lock and write: a fence or expiry
		// discovered here aborts the transaction, so no claim becomes fresh.
		if claim && current(ctx, q, p, a, r, row.EffectiveExpiresAt.Time) != nil {
			return privacy.ErrExpired
		}
		state, fresh = next, isFresh
		return nil
	})
	if err != nil {
		return artifact.StreamingState{}, false, err
	}
	return state, fresh, nil
}

// ReadStreaming returns the journal for cleanup and reconciliation. It is
// control metadata only, never an access check.
func (l *Ledger) ReadStreaming(ctx context.Context, plan artifact.StreamingPlan) (artifact.StreamingState, error) {
	var state artifact.StreamingState
	if plan.Validate() != nil {
		return state, artifact.ErrInvalid
	}
	plan.Registration = normalized(plan.Registration)
	err := l.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.LockAttempt(ctx, id(plan.Registration.Location.AttemptID))
		if err != nil || !bytes.Equal(row.RequestDigest, digest(plan.Registration)) {
			return privacy.ErrConflict
		}
		stream, err := q.LockStream(ctx, row.ID)
		if err != nil || !bytes.Equal(stream.PlanDigest, digest(plan)) {
			return privacy.ErrConflict
		}
		d := json.NewDecoder(bytes.NewReader(stream.State))
		d.DisallowUnknownFields()
		if d.Decode(&state) != nil || state.Validate(plan) != nil {
			return privacy.ErrUnavailable
		}
		return nil
	})
	return state, err
}

func releaseStreamWithAttempt(ctx context.Context, q *custodydb.Queries, allocation, attempt pgtype.UUID, now time.Time) error {
	stream, err := q.LockStream(ctx, attempt)
	if err != nil {
		return privacy.ErrUnavailable
	}
	if stream.ReleasedAt.Valid {
		return nil
	}
	var state artifact.StreamingState
	if json.Unmarshal(stream.State, &state) != nil {
		return privacy.ErrUnavailable
	}
	state.Aborted, state.ReleasedAt = true, now // absence proven by the attempt purge
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	changed, err := q.ReleaseStreamingTemporary(ctx, custodydb.ReleaseStreamingTemporaryParams{ID: allocation, ChargedBytes: stream.TemporaryBytes, ChargedObjects: stream.TemporaryObjects})
	if err != nil || changed != 1 {
		return privacy.ErrUnavailable
	}
	changed, err = q.UpdateStream(ctx, custodydb.UpdateStreamParams{AttemptID: attempt, State: encoded, Revision: stream.Revision, ReleasedAt: ts(now)})
	if err != nil || changed != 1 {
		return privacy.ErrUnavailable
	}
	return nil
}
