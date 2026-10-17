package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// CompleteNativeOperation is a positive handoff, distinct from idempotent
// restrictive cleanup. Only one acknowledged exact open-to-closed transition
// qualifies; absence, earlier cleanup and an unknown COMMIT never imply success.
// The caller has just completed the ordinary current frame gate. This operation
// can only reduce authority, and its result permits only the final zero-byte
// marker under that same original lease. It refunds no owner/key/history spend.
func (s *NativeOwners) CompleteNativeOperation(ctx context.Context, l value.NativeLease) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !l.Valid(time.Now()) || !l.Operation.CurrentValid(time.Now()) || l.Operation.Reference.InstallationID != s.workers.profile.InstallationID {
		return artifact.ErrDownloadUnavailable
	}
	call, stop := context.WithDeadline(ctx, l.Until)
	defer stop()
	err := s.workers.downloads.ledger.transaction(call, func(q *custodydb.Queries) error {
		row, e := q.LockNativeOwner(call, custodydb.LockNativeOwnerParams{WorkerID: id(l.Operation.Reference.WorkerID), RootID: id(s.workers.downloads.root)})
		if e != nil {
			return e
		}
		clock, e := q.CurrentTime(call)
		if e != nil || !nativeCompletionRecordValid(row, l, clock.Time) || call.Err() != nil {
			return artifact.ErrDownloadUnavailable
		}
		n, e := q.CloseNativeOwner(call, custodydb.CloseNativeOwnerParams{WorkerID: row.WorkerID, RootID: row.RootID, OperationID: row.OperationID, Fence: row.Fence})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadUnavailable
		}
		// The close trigger can wait on its backing lock. Recheck the original lease
		// after that wait; expiry may not turn a restrictive write into terminal proof.
		clock, e = q.CurrentTime(call)
		if e != nil || call.Err() != nil || !l.Valid(clock.Time) || !clock.Time.Before(row.LeaseUntil.Time) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
	if err != nil {
		return err
	}
	if call.Err() != nil || !l.Valid(time.Now()) {
		return artifact.ErrDownloadExpired
	}
	return nil
}
func nativeCompletionRecordValid(row custodydb.DownloadNativeOwner, l value.NativeLease, now time.Time) bool {
	actual, _, err := decodeNativeOwner(row)
	return err == nil && !row.Closed && !row.RetiredAt.Valid && actual.Equal(l.Operation) && row.LeaseSequence == l.Sequence && l.Valid(now) && actual.CurrentValid(now) && row.LeaseUntil.Valid && now.Before(row.LeaseUntil.Time) && !l.Until.After(row.LeaseUntil.Time)
}
