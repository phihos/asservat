package kms

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This private operation is made only for one of the enclosing concrete
// worker's closed credential slots. Two committed recovery observations of
// the same revision bracket each provider effect; no SQL transaction is held
// over provider I/O.
type configurationProviderRefreshOperation struct {
	worker   *InstalledConfigurationProviderEffects
	recovery fleet.RecoveryState
	material contracts.OwnerStorageCredential
	until    time.Time
	finished bool
	stops    []context.CancelFunc
}

func (s *InstalledConfigurationProviderEffects) beginRefresh(ctx context.Context, slot *ownerProviderLifetime) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || s.effects == nil || (slot != s.effects.wrap && slot != s.effects.unwrap && !s.effects.cleanupSlot(slot)) {
		return nil, time.Time{}, ErrKeyService
	}
	return s.beginConfigurationOperation(ctx)
}

// Shared private mechanics for fixed configuration/cleanup purposes and owner
// configuration audit. Public callers cannot supply phases or proof callbacks.
func (s *InstalledConfigurationProviderEffects) beginConfigurationOperation(ctx context.Context) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil || s.effects == nil || s.recovery == nil {
		return nil, time.Time{}, ErrKeyService
	}
	until, ok := ctx.Deadline()
	if !ok {
		return nil, time.Time{}, ErrKeyService
	}
	p := &configurationProviderRefreshOperation{worker: s, until: until}
	complete := false
	defer func() {
		if !complete {
			p.close()
		}
	}()
	var err error
	p.recovery, err = s.recoveryCurrent(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	p.until = identity.Earlier(p.until, p.recovery.FreshUntil)
	call, end := context.WithDeadline(ctx, p.until)
	p.stops = append(p.stops, end)
	if p.material, err = s.auditCredential(call); err != nil {
		return nil, time.Time{}, err
	}
	last, err := s.recoveryCurrent(call)
	if err != nil || !configurationProviderSameRecovery(p.recovery, last, time.Now()) {
		return nil, time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, last.FreshUntil)
	if call.Err() != nil || !time.Now().Before(p.until) {
		return nil, time.Time{}, ErrKeyService
	}
	complete = true
	return p, p.until, nil
}

// finish confirms the same recovery revision after the effect.
func (p *configurationProviderRefreshOperation) finish(ctx context.Context) (time.Time, error) {
	if p == nil || p.finished || p.worker == nil || ctx == nil || ctx.Err() != nil || p.worker.root.Err() != nil {
		return time.Time{}, ErrKeyService
	}
	p.finished = true // a failed/unknown final read is never retried in this refresh
	if end, ok := ctx.Deadline(); ok {
		p.until = identity.Earlier(p.until, end)
	}
	call, end := context.WithDeadline(ctx, p.until)
	defer end()
	last, err := p.worker.recoveryCurrent(call)
	if err != nil || !configurationProviderSameRecovery(p.recovery, last, time.Now()) {
		return time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, last.FreshUntil)
	if call.Err() != nil || p.worker.root.Err() != nil || !time.Now().Before(p.until) {
		return time.Time{}, ErrKeyService
	}
	return p.until, nil
}

func configurationProviderSameRecovery(original, current fleet.RecoveryState, now time.Time) bool {
	return original.Valid(now) && current.Valid(now) && current.InstallationID == original.InstallationID && current.IssuerEpoch == original.IssuerEpoch && current.Revision == original.Revision
}

func (p *configurationProviderRefreshOperation) close() {
	if p == nil {
		return
	}
	for i := len(p.stops) - 1; i >= 0; i-- {
		p.stops[i]()
	}
	p.stops = nil
	p.material = contracts.OwnerStorageCredential{}
}
