package bootstrap

import (
	"context"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

var _ app.ConnectorLeafRegistryAt = (*RegionalLifecycle)(nil)

// ConnectorLeafRegistrationAt lends the exact executor-owned opening source to
// one read-only registration conversation. The caller must close its enclosing
// native source bracket before using this result. No lifecycle effect or source
// acceptance may use this reader; the ordinary registry method is unchanged.
func (r *RegionalLifecycle) ConnectorLeafRegistrationAt(ctx context.Context, leaf value.ConnectorCredentialCertificate, source value.ConnectorIdentitySource) (app.ConnectorLeafRegistration, error) {
	var zero app.ConnectorLeafRegistration
	if r == nil || r.Local == nil || r.Now == nil || ctx == nil || ctx.Err() != nil || !source.Valid(r.Now()) || !leaf.Valid(r.Now()) || source.Observation.Profile.Binding != leaf.Binding || source.Observation.Profile.RootID != r.Credential.Profile.RootID {
		return zero, value.ErrUnavailable
	}
	until := source.Observation.FreshUntil
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	source.Observation.Profile = source.Observation.Profile.Clone()
	source.Observation.FreshUntil = until
	local := &regionalRegistrationSource{root: call, source: source, now: r.Now}
	defer local.close()
	registered, err := r.connectorLeafRegistration(call, leaf, local)
	if err != nil || !local.complete() || !registered.Valid(r.Now()) || registered.Revision != source.Observation.Profile.Revision {
		return zero, value.ErrUnavailable
	}
	registered.FreshUntil = identity.Earlier(registered.FreshUntil, until)
	if call.Err() != nil || !registered.Valid(r.Now()) {
		return zero, value.ErrUnavailable
	}
	return registered, nil
}

// This reader is created privately for one Run and is never installed into
// RegionalLifecycle.Local. Only the fixed registry's two source callbacks are
// permitted; neither callback re-anchors the original native observation.
type regionalRegistrationSource struct {
	mu     sync.Mutex
	root   context.Context
	source value.ConnectorIdentitySource
	now    func() time.Time
	reads  int
	closed bool
}

func (s *regionalRegistrationSource) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx == nil || ctx.Err() != nil || s.root.Err() != nil || s.reads >= 2 || !s.source.Valid(s.now()) {
		s.closed = true
		return value.ConnectorIdentitySource{}, value.ErrUnavailable
	}
	s.reads++
	out := s.source
	out.Observation.Profile = out.Observation.Profile.Clone()
	if until, ok := ctx.Deadline(); ok {
		out.Observation.FreshUntil = identity.Earlier(out.Observation.FreshUntil, until)
	}
	if !out.Valid(s.now()) || ctx.Err() != nil || s.root.Err() != nil {
		s.closed = true
		return value.ConnectorIdentitySource{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *regionalRegistrationSource) BeginConnectorLifecycle(context.Context, app.ConnectorLifecycleRequest) (app.ConnectorLifecycleOperation, error) {
	s.close()
	return nil, value.ErrDenied
}

func (s *regionalRegistrationSource) ReadConnectorIdentityConfiguration(context.Context) (app.ConnectorIdentityConfiguration, error) {
	s.close()
	return app.ConnectorIdentityConfiguration{}, value.ErrDenied
}

func (s *regionalRegistrationSource) complete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.reads == 2 && s.root.Err() == nil && s.source.Valid(s.now())
}

func (s *regionalRegistrationSource) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}
