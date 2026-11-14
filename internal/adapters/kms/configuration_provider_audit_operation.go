package kms

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// ConfigurationProviderAuditOperation owns the current material, native
// interval around one encrypted owner audit/readback within the application
// owned FIFO ticket, which is consumed exactly once and released after join.
// It is minted only by the installed two-purpose worker; copies and repeated
// final reads cannot complete another operation. It supplies no SQL acceptance.
type ConfigurationProviderAuditOperation struct {
	self                   *ConfigurationProviderAuditOperation
	worker                 *InstalledConfigurationProviderEffects
	mu                     sync.Mutex
	ctx                    context.Context
	cancel                 context.CancelFunc
	changed                chan struct{}
	busy, closed, finished bool
	closeOnce              sync.Once
	endBorrow              func()
	native                 *configurationProviderRefreshOperation
	configuration          fleet.OwnerConfiguration
	material               contracts.OwnerStorageCredential
	// authority marks an ADR-189 permission authority audit, which has no
	// owner configuration to match.
	authority bool
}

// No token is borrowed, exposed or renewed by this local availability hint.
// Actual effects still use the existing purpose-fixed finite token borrows.
func (s *ownerProviderLifetime) configurationAuditAvailable() bool {
	if s == nil || s.control == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.closing && s.root.Err() == nil && !s.active && !s.uncertain && s.current != nil &&
		s.borrows < s.limit && s.control.now().Before(s.current.value.until)
}

func (s *InstalledConfigurationProviderEffects) configurationAuditAvailable() bool {
	return s != nil && s.effects != nil && s.effects.wrap.configurationAuditAvailable() && s.effects.unwrap.configurationAuditAvailable()
}

// AuditAvailable reports whether both audit provider slots currently hold a
// login, so a loop can wait for the first login instead of failing at
// BeginAuthorityAudit. It is scheduling only; Begin rechecks everything.
func (s *InstalledConfigurationProviderEffects) AuditAvailable() bool {
	return s.configurationAuditAvailable()
}

func (s *InstalledConfigurationProviderEffects) BeginOwnerConfigurationAudit(ctx context.Context, c fleet.OwnerConfiguration) (*ConfigurationProviderAuditOperation, error) {
	if s == nil || s.admission == nil || ctx == nil || ctx.Err() != nil || !c.Valid() ||
		c.Pool.InstallationID != s.input.InstallationID || c.Pool.ClusterID != s.input.ClusterID ||
		c.Pool.NamespaceUID != s.input.NamespaceUID || c.Revision.UID != s.input.OwnerSourceUID || !s.configurationAuditAvailable() || !s.admission.ClaimOwnerAudit(ctx) {
		return nil, ErrKeyService
	}
	return s.beginAudit(ctx, &ConfigurationProviderAuditOperation{configuration: c.Clone()})
}

// BeginAuthorityAudit is the ADR-189 sibling for one permission authority
// record: the same audit-only material under the same native interval. The
// caller scopes the object key to its own stream root.
func (s *InstalledConfigurationProviderEffects) BeginAuthorityAudit(ctx context.Context) (*ConfigurationProviderAuditOperation, error) {
	if s == nil || s.admission == nil || ctx == nil || ctx.Err() != nil || !s.configurationAuditAvailable() || !s.admission.ClaimAuthorityAudit(ctx) {
		return nil, ErrKeyService
	}
	return s.beginAudit(ctx, &ConfigurationProviderAuditOperation{authority: true})
}

func (s *InstalledConfigurationProviderEffects) beginAudit(ctx context.Context, p *ConfigurationProviderAuditOperation) (*ConfigurationProviderAuditOperation, error) {
	// The application acquired its fixed ticket before selecting this exact
	// candidate. Its unchanged end bounds all work here; no nested ticket,
	// new source selection or renewed interval is introduced by this borrow.
	call, end, err := s.borrow(ctx)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithCancel(call)
	p.worker, p.ctx, p.cancel, p.endBorrow, p.changed = s, call, cancel, end, make(chan struct{})
	p.self = p
	complete := false
	defer func() {
		if !complete {
			p.Close()
		}
	}()
	p.native, _, err = s.beginConfigurationOperation(call)
	if err != nil || call.Err() != nil || !time.Now().Before(p.native.until) {
		return nil, ErrKeyService
	}
	p.material = p.native.material
	// Keep the initial recovery end visible to the actual S3/KMS I/O.
	// Close also cancels the parent call owned by endBorrow.
	parentCancel := p.cancel
	narrowed, narrowCancel := context.WithDeadline(call, p.native.until)
	p.ctx, p.cancel = narrowed, func() { narrowCancel(); parentCancel() }
	complete = true
	return p, nil
}

func (p *ConfigurationProviderAuditOperation) Context() context.Context {
	if p == nil || p.self != p {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return p.ctx
}

func (p *ConfigurationProviderAuditOperation) Credentials() (contracts.OwnerStorageCredential, error) {
	if p == nil || p.self != p {
		return contracts.OwnerStorageCredential{}, ErrKeyService
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.finished || p.ctx.Err() != nil || !time.Now().Before(p.native.until) {
		return contracts.OwnerStorageCredential{}, ErrKeyService
	}
	return p.material, nil
}

// Finish belongs after the actual encrypted write and independent readback.
// The two post-effect SQL reads bracket genuine final native/material reads.
func (p *ConfigurationProviderAuditOperation) Finish() error {
	if p == nil || p.self != p {
		return ErrKeyService
	}
	p.mu.Lock()
	if p.closed || p.finished || p.busy || p.ctx.Err() != nil {
		p.mu.Unlock()
		return ErrKeyService
	}
	p.busy, p.finished = true, true
	p.mu.Unlock()
	_, err := p.native.finish(p.ctx)
	p.mu.Lock()
	p.busy = false
	close(p.changed)
	p.changed = make(chan struct{})
	if p.closed || p.ctx.Err() != nil {
		err = ErrKeyService
	}
	if err != nil {
		p.cancel()
	}
	p.mu.Unlock()
	return err
}

// The application retains its ticket until this operation and the actual
// Store/response owners have joined. Final native reads are also joined, including blocked responses.
func (p *ConfigurationProviderAuditOperation) Close() {
	if p == nil || p.self != p {
		return
	}
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		for p.busy {
			changed := p.changed
			p.mu.Unlock()
			<-changed
			p.mu.Lock()
		}
		p.material = contracts.OwnerStorageCredential{}
		p.mu.Unlock()
		if p.native != nil {
			p.native.close()
		}
		p.endBorrow()
	})
}
