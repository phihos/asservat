package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// ReadCleanup shares the exact current installed-worker proof with capacity,
// but can return only the fixed cleanup receipt. Pending is a positive current
// observation, never a fallback for failed guard, journal or metadata reads.
func (s *InstalledWorkerProjectionReader) ReadCleanup(ctx context.Context) (contracts.CaptureCleanupProjectionClaim, bool, time.Time, error) {
	var zero contracts.CaptureCleanupProjectionClaim
	call, end, state, until, err := s.beginObservation(ctx)
	if err != nil {
		return zero, false, time.Time{}, err
	}
	defer end()
	p := state.CleanupProjection
	if p != nil && p.Receipt != nil {
		r := p.Receipt
		if err = s.projectionMetadata(call, state.SetupID, p.OperationID, p.PublicDigest, r.Secret, r.ResourceVersion); err != nil {
			return zero, false, time.Time{}, err
		}
	} else {
		until = identity.Earlier(until, state.Until)
	}
	until, err = s.finishObservation(call, until)
	if err != nil {
		return zero, false, time.Time{}, err
	}
	if p == nil || p.Receipt == nil {
		return zero, false, until, nil
	}
	return *p, true, until, nil
}
