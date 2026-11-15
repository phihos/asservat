package capture

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

// contextStorageWait keeps the selection an earlier preview read. Storage is
// a standing row that the reader creates on first use (capacity_enroll), so
// there is nothing to wait for.
type contextStorageWait struct {
	selection value.ContextStorageSelection
}

func (s ContextInvestigation) beginStorageWait(_ context.Context, _ targets.PodResolution, _ time.Time, selection value.ContextStorageSelection) *contextStorageWait {
	return &contextStorageWait{selection: selection}
}

func (w *contextStorageWait) close() {}

type contextStorageSelectionChange struct{}

func (contextStorageSelectionChange) Error() string { return "context storage selection changed" }
func (contextStorageSelectionChange) Unwrap() error { return value.ErrChanged }

func (s ContextInvestigation) consumeStorage(ctx context.Context, f contextFacts, _ value.ContextIntent, w *contextStorageWait) (ContextStorageObservation, error) {
	var zero ContextStorageObservation
	if why := s.nonStorageFactsFailure(f, s.Now()); why != "" {
		return zero, previewFailure("facts/current/"+why, value.ErrChanged)
	}
	v, err := s.Storage.ContextStorage(ctx, f.target.Target())
	if err != nil {
		return zero, previewFailure("facts/storage", err)
	}
	if !s.storageCurrent(v, f.target.Target(), s.Now()) {
		return zero, previewFailure("facts/current/storage", value.ErrChanged)
	}
	if w.selection != (value.ContextStorageSelection{}) && w.selection != v.Selection {
		return zero, previewFailure("facts/storage", contextStorageSelectionChange{})
	}
	return v, nil
}
