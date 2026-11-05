package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5"
)

// reserveProfileStreamLocked joins profile/log admission's existing allocation/attempt
// transaction. No writer exists yet: reserve every multipart obligation now,
// and leave the journal unusable until accepted execution chooses a process.
func reserveProfileStreamLocked(ctx context.Context, q *custodydb.Queries, r artifact.Registration) error {
	if r.NativeLimit <= artifact.FrameBytes {
		return nil
	}
	if r.NativeLimit > artifact.MaxGoTraceBytes {
		return artifact.ErrInvalid
	}
	plan := artifact.StreamingPlan{Registration: normalized(r)}
	old, err := q.LockStream(ctx, id(r.Location.AttemptID))
	if err == nil {
		if old.TemporaryBytes != plan.TemporaryBytes() || old.TemporaryObjects != int64(1+plan.PartLimit()) {
			return privacy.ErrConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	changed, err := q.ChargeStreaming(ctx, custodydb.ChargeStreamingParams{ID: id(r.AllocationID), ChargedBytes: plan.TemporaryBytes(), ChargedObjects: int64(1 + plan.PartLimit())})
	if err != nil {
		return err
	}
	if changed != 1 {
		return privacy.ErrCapacity
	}
	state, err := json.Marshal(artifact.StreamingState{})
	if err != nil {
		return err
	}
	return q.InsertPendingStream(ctx, custodydb.InsertPendingStreamParams{AttemptID: id(r.Location.AttemptID), TemporaryBytes: plan.TemporaryBytes(), TemporaryObjects: int64(1 + plan.PartLimit()), State: state})
}

// bindProfileStreamLocked runs only inside the original API preparation's
// current authority transaction. A replay observes the same immutable binding;
// it cannot change epochs, reset spend, or acquire a new remote-write permit.
func bindProfileStreamLocked(ctx context.Context, q *custodydb.Queries, e artifact.ContextExpectation, epoch string, first bool) error {
	if e.Profile == nil && e.Logs == nil || e.Registration.NativeLimit <= artifact.FrameBytes {
		return nil
	}
	if e.Logs != nil && e.Validate() != nil {
		return artifact.ErrInvalid
	}
	plan := artifact.StreamingPlan{Registration: normalized(e.Registration), WriterEpoch: epoch}
	if plan.Validate() != nil {
		return artifact.ErrInvalid
	}
	old, err := q.LockStream(ctx, id(e.Registration.Location.AttemptID))
	if err != nil {
		return err
	}
	if old.TemporaryBytes != plan.TemporaryBytes() || old.TemporaryObjects != int64(1+plan.PartLimit()) || old.ReleasedAt.Valid {
		return privacy.ErrConflict
	}
	if old.WriterEpoch.Valid || len(old.PlanDigest) > 0 {
		if uid(old.WriterEpoch) != epoch || !bytes.Equal(old.PlanDigest, digest(plan)) {
			return privacy.ErrConflict
		}
		return nil
	}
	if !first {
		return privacy.ErrConflict
	}
	changed, err := q.BindPendingStream(ctx, custodydb.BindPendingStreamParams{AttemptID: old.AttemptID, WriterEpoch: id(epoch), PlanDigest: digest(plan)})
	if err != nil {
		return err
	}
	if changed != 1 {
		return privacy.ErrConflict
	}
	return nil
}
