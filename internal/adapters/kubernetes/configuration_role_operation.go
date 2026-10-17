package kubernetes

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Private, operation-local observation. No value supplied through a decoded
// contract can create this slot. Independent calls never share it.
type configurationRoleOperationKey struct{}
type configurationRoleObserved struct {
	observation                       contracts.ConfigurationRoleObservation
	deploymentVersion, accountVersion string
	guards                            [3]string
	native                            *configurationRoleNativeResponses
}
type configurationRoleOperation struct {
	mu     sync.Mutex
	source *ConfigurationRoleSource
	ctx    context.Context
	closed bool
	proof  *configurationRoleObserved
	// rechecked: a full recheck followed the opening proof (ADR-188).
	rechecked bool
}

func (s *ConfigurationRoleSource) operation(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	if p, ok := ctx.Value(configurationRoleOperationKey{}).(*configurationRoleOperation); ok {
		p.mu.Lock()
		valid := p.source == s && !p.closed && p.ctx.Err() == nil
		p.mu.Unlock()
		if !valid {
			return nil, nil, cfg.ErrUnavailable
		}
		return ctx, func() {}, nil
	}
	live, end := context.WithTimeout(ctx, 5*time.Second)
	p := &configurationRoleOperation{source: s, ctx: live}
	return context.WithValue(live, configurationRoleOperationKey{}, p), func() {
		end()
		p.mu.Lock()
		p.closed, p.proof = true, nil
		p.mu.Unlock()
	}, nil
}

// The callback is the one fixed SQL role operation (or final verification),
// never a public request or arbitrary authority provider. Close cancels and
// joins it along with the root's existing operations.
func (s *ConfigurationRuntimeRoleRoot) WithConfigurationRoleOperation(ctx context.Context, run func(context.Context) error) error {
	if s == nil || run == nil || ctx == nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return cfg.ErrUnavailable
	}
	s.joined.Add(1)
	s.mu.Unlock()
	defer s.joined.Done()
	live, cancel := context.WithCancel(ctx)
	joined := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { cancel(); close(joined) })
	defer func() {
		cancel()
		if !stop() {
			<-joined
		}
	}()
	bound, finish, e := s.source.operation(live)
	if e != nil {
		return e
	}
	defer finish()
	e = run(bound)
	if e == nil && bound.Err() != nil {
		return cfg.ErrUnavailable
	}
	return e
}

func (s *ConfigurationRoleSource) ReadConfigurationRoleSource(ctx context.Context) (contracts.ConfigurationRoleObservation, error) {
	var zero contracts.ConfigurationRoleObservation
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	live, finish, e := s.operation(ctx)
	if e != nil {
		return zero, e
	}
	defer finish()
	p := live.Value(configurationRoleOperationKey{}).(*configurationRoleOperation)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil || live.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	var proof configurationRoleObserved
	if p.proof == nil {
		proof, e = s.readConfigurationRoleSource(live)
	} else {
		proof, e = s.recheckConfigurationRoleSource(live, *p.proof)
	}
	if e != nil || live.Err() != nil {
		p.closed, p.proof = true, nil
		// Normalized to unavailable; only the fixed check codes survive.
		if codes := configurationSourceCodes(e); codes != nil {
			return zero, errors.Join(cfg.ErrUnavailable, codes)
		}
		return zero, cfg.ErrUnavailable
	}
	p.rechecked = p.rechecked || p.proof != nil
	p.proof = &proof
	return proof.observation, nil
}

// latestConfigurationRoleSource reuses the operation's latest proof without
// new I/O once a recheck followed the opening proof: the role step's post-lock
// recheck before the CREATE effect (ADR-188). Otherwise it proves afresh.
func (s *ConfigurationRoleSource) latestConfigurationRoleSource(ctx context.Context) (contracts.ConfigurationRoleObservation, error) {
	var zero contracts.ConfigurationRoleObservation
	p, ok := ctx.Value(configurationRoleOperationKey{}).(*configurationRoleOperation)
	if !ok {
		return s.ReadConfigurationRoleSource(ctx)
	}
	p.mu.Lock()
	reuse := p.source == s && p.rechecked && p.proof != nil
	p.mu.Unlock()
	if !reuse {
		return s.ReadConfigurationRoleSource(ctx)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.proof == nil || p.ctx.Err() != nil || ctx.Err() != nil || !configurationRoleSourceMatches(s.input, p.proof.observation, s.client.now()) {
		return zero, cfg.ErrUnavailable
	}
	return p.proof.observation, nil
}
