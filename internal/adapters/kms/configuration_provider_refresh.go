package kms

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// This private operation is made only for one of the enclosing concrete
// worker's closed credential slots. No SQL transaction is held over provider I/O.
type configurationProviderRefreshOperation struct {
	worker   *InstalledConfigurationProviderEffects
	material contracts.OwnerStorageCredential
	until    time.Time
	finished bool
	stops    []context.CancelFunc
}

func (s *InstalledConfigurationProviderEffects) beginRefresh(ctx context.Context, slot *ownerProviderLifetime) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || s.effects == nil || (slot != s.effects.wrap && slot != s.effects.unwrap) {
		return nil, time.Time{}, ErrKeyService
	}
	return s.beginConfigurationOperation(ctx)
}

// Shared private mechanics for fixed configuration/cleanup purposes and owner
// configuration audit. Public callers cannot supply phases or proof callbacks.
func (s *InstalledConfigurationProviderEffects) beginConfigurationOperation(ctx context.Context) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil || s.effects == nil {
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
	call, end := context.WithDeadline(ctx, p.until)
	p.stops = append(p.stops, end)
	var err error
	if p.material, err = s.auditCredential(call); err != nil {
		return nil, time.Time{}, err
	}
	if call.Err() != nil || !time.Now().Before(p.until) {
		return nil, time.Time{}, ErrKeyService
	}
	complete = true
	return p, p.until, nil
}

// finish confirms the original deadline after the effect.
func (p *configurationProviderRefreshOperation) finish(ctx context.Context) (time.Time, error) {
	if p == nil || p.finished || p.worker == nil || ctx == nil || ctx.Err() != nil || p.worker.root.Err() != nil {
		return time.Time{}, ErrKeyService
	}
	p.finished = true // a finished refresh is never retried
	if end, ok := ctx.Deadline(); ok {
		p.until = identity.Earlier(p.until, end)
	}
	if ctx.Err() != nil || p.worker.root.Err() != nil || !time.Now().Before(p.until) {
		return time.Time{}, ErrKeyService
	}
	return p.until, nil
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
