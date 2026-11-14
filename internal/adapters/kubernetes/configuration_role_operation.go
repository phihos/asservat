package kubernetes

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
)

// Private, operation-local observation. No value supplied through a decoded
// contract can create this slot. Independent calls never share it.
type configurationRoleOperationKey struct{}
type configurationRoleObserved struct {
	observation    contracts.ConfigurationRoleObservation
	deployment     *apps.Deployment
	accountVersion string
	guards         [3]string
	native         *configurationRoleNativeResponses
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
