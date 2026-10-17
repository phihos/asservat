package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// These fixed worker2 hints perform one actual original-journal GET. The bool
// can only schedule a subsequent full current operation: no receipt, authority
// interval, credentials or replacement source is returned. Missing or malformed
// state never becomes a successful empty observation.
func (s *InstalledWorkerProjectionReader) CapacityProjectionHint(ctx context.Context) (bool, error) {
	state, err := s.projectionHintState(ctx)
	if err != nil {
		return false, err
	}
	positive := state.CapacityProjection != nil && state.CapacityProjection.Receipt != nil
	if !positive && !s.client.now().Before(state.Until) {
		return false, cfg.ErrUnavailable
	}
	return positive, nil
}

func (s *InstalledWorkerProjectionReader) CleanupProjectionHint(ctx context.Context) (bool, error) {
	state, err := s.projectionHintState(ctx)
	if err != nil {
		return false, err
	}
	positive := state.CleanupProjection != nil && state.CleanupProjection.Receipt != nil
	if !positive && !s.client.now().Before(state.Until) {
		return false, cfg.ErrUnavailable
	}
	return positive, nil
}

// PermissionProjectionHint is the ADR-189 sibling. A permission projection
// may appear after the journal end only if its receipt was acknowledged.
func (s *InstalledWorkerProjectionReader) PermissionProjectionHint(ctx context.Context) (bool, error) {
	state, err := s.projectionHintState(ctx)
	if err != nil {
		return false, err
	}
	positive := state.PermissionProjection != nil && state.PermissionProjection.Receipt != nil
	if !positive && !s.client.now().Before(state.Until) {
		return false, cfg.ErrUnavailable
	}
	return positive, nil
}

func (s *InstalledWorkerProjectionReader) projectionHintState(ctx context.Context) (contracts.InitialRuntimeResourceState, error) {
	var zero contracts.InitialRuntimeResourceState
	if s == nil || s.client == nil || s.input.Activation == nil ||
		s.input.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, s.client.now().Add(5*time.Second))
	defer end()
	state, err := s.journal(call)
	if err != nil {
		return zero, err
	}
	until, _ := call.Deadline()
	if err = initialHandoverDeadline(call, s.client.now, until); err != nil {
		return zero, err
	}
	return state, nil
}
