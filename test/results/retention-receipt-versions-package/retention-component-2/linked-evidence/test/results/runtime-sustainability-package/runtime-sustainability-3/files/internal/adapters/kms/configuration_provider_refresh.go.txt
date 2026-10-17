package kms

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This private operation is made only for one of the enclosing concrete
// worker's two fixed credential slots. It is never selected by a callback or
// exposed as a current-reader implementation. Native and SQL are both real;
// no SQL transaction is held over native/provider I/O.
type configurationProviderRefreshOperation struct {
	worker   *InstalledConfigurationProviderEffects
	native   *kubernetes.ConfigurationWorkerProviderOperation
	recovery fleet.RecoveryState
	manifest contracts.ConfigurationRuntimeCredentialManifest
	mounted  map[string][]byte
	until    time.Time
	finished bool
	stops    []context.CancelFunc
}

func (s *InstalledConfigurationProviderEffects) beginRefresh(ctx context.Context, slot *ownerProviderLifetime) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || s.effects == nil || (slot != s.effects.wrap && slot != s.effects.unwrap) {
		return nil, time.Time{}, ErrKeyService
	}
	return s.beginConfigurationNative(ctx)
}

// Shared private mechanics for only the two fixed refresh purposes and owner
// configuration audit. Public callers cannot supply phases or proof callbacks.
func (s *InstalledConfigurationProviderEffects) beginConfigurationNative(ctx context.Context) (*configurationProviderRefreshOperation, time.Time, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil || s.effects == nil ||
		s.reader == nil || s.recovery == nil {
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
	p.recovery, err = s.recovery.RecoveryState(ctx)
	if err != nil || !p.recovery.Valid(time.Now()) || p.recovery.InstallationID != s.input.InstallationID {
		return nil, time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, p.recovery.FreshUntil)
	call, end := context.WithDeadline(ctx, p.until)
	p.stops = append(p.stops, end)
	p.manifest, p.mounted, err = s.mounted(call)
	if err != nil {
		return nil, time.Time{}, ErrKeyService
	}
	p.native, err = s.reader.BeginConfigurationProviderOperation(call, p.recovery.IssuerEpoch, p.manifest, p.mounted)
	if err != nil {
		return nil, time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, p.native.FreshUntil())
	call, narrow := context.WithDeadline(call, p.until)
	p.stops = append(p.stops, narrow)
	last, err := s.recovery.RecoveryState(call)
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

func (p *configurationProviderRefreshOperation) finish(ctx context.Context) (time.Time, error) {
	if p == nil || p.finished || p.native == nil || p.worker == nil || ctx == nil || ctx.Err() != nil || p.worker.root.Err() != nil {
		return time.Time{}, ErrKeyService
	}
	p.finished = true // a failed/unknown final read is never retried in this refresh
	if end, ok := ctx.Deadline(); ok {
		p.until = identity.Earlier(p.until, end)
	}
	call, end := context.WithDeadline(ctx, p.until)
	defer end()
	first, err := p.worker.recovery.RecoveryState(call)
	if err != nil || !configurationProviderSameRecovery(p.recovery, first, time.Now()) {
		return time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, first.FreshUntil)
	call, narrow := context.WithDeadline(call, p.until)
	defer narrow()
	manifest, mounted, err := p.worker.mounted(call)
	if err != nil {
		return time.Time{}, ErrKeyService
	}
	defer func() {
		for _, value := range mounted {
			clear(value)
		}
	}()
	// Manifest bytes are among the compared mounted files. The native handle
	// independently compares the actual immutable SQL3 and selected Secret to
	// its own cloned original bytes; a same-UID rotation cannot be adopted here.
	if manifest.RootUID != p.manifest.RootUID || manifest.SetupID != p.manifest.SetupID || len(mounted) != len(p.mounted) {
		return time.Time{}, ErrKeyService
	}
	for name, value := range p.mounted {
		if !bytes.Equal(mounted[name], value) {
			return time.Time{}, ErrKeyService
		}
	}
	until, err := p.worker.reader.FinishConfigurationProviderOperation(call, p.native)
	if err != nil {
		return time.Time{}, ErrKeyService
	}
	p.until = identity.Earlier(p.until, until)
	call, finalEnd := context.WithDeadline(call, p.until)
	defer finalEnd()
	last, err := p.worker.recovery.RecoveryState(call)
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
	if p.native != nil {
		p.native.Close()
	}
	for _, value := range p.mounted {
		clear(value)
	}
	p.mounted = nil
}
