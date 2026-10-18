package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/adapters/mtls"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// BeginAPIContextSetup owns one complete native proof for this exact setup,
// with the generation attached under the proof state's lock. A later read of
// the current generation can never make an older proof usable again.
func (p *ConnectorAPIExecutionProcess) BeginAPIContextSetup(ctx context.Context, credentials *mtls.ConnectorProcessCredentials) (mtls.ContextStartProcessSetup, error) {
	if p == nil || p.guard == nil || p.parent == nil || ctx == nil || ctx.Err() != nil || p.parent.Err() != nil || credentials == nil || credentials != p.guard.credentials {
		return nil, cfg.ErrUnavailable
	}
	call, stopCall := context.WithCancel(ctx)
	ended := make(chan struct{})
	stopParent := context.AfterFunc(p.parent, func() { stopCall(); close(ended) })
	defer func() {
		stopCall()
		if !stopParent() {
			<-ended
		}
	}()
	proof, err := p.guard.current(call)
	if err != nil || proof.proof.Process != p.connector || !proof.source.Valid(p.guard.attester.client.now()) {
		return nil, cfg.ErrUnavailable
	}
	root, cancel := context.WithDeadline(ctx, proof.validUntil)
	op := &connectorAPISetup{process: p, credentials: credentials, root: root, cancel: cancel, proof: proof, finishNative: p.guard.finishSetup, parentDone: make(chan struct{})}
	op.stopParent = context.AfterFunc(p.parent, func() { cancel(); close(op.parentDone) })
	if _, _, err = op.ReadAPIProcessConnector(root, credentials); err != nil {
		op.Close()
		return nil, err
	}
	return op, nil
}

type connectorAPISetup struct {
	process      *ConnectorAPIExecutionProcess
	credentials  *mtls.ConnectorProcessCredentials
	root         context.Context
	cancel       context.CancelFunc
	parentDone   chan struct{}
	stopParent   func() bool
	mu           sync.Mutex
	joined       sync.WaitGroup
	closeOnce    sync.Once
	proof        connectorAPIProof
	finishNative func(context.Context, connectorAPIProof) (connectorAPIProof, error)
	sourceUsed   bool
	finishing    bool
	finished     bool
	closed       bool
}

func (o *connectorAPISetup) currentLocked(ctx context.Context) bool {
	if o.closed || ctx == nil || ctx.Err() != nil || o.root.Err() != nil || o.process.parent.Err() != nil || !o.proof.valid(o.process.guard.attester.client.now()) {
		return false
	}
	s := &o.process.guard.reuse
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation == o.proof.generation
}

func (o *connectorAPISetup) ReadAPIProcessConnector(ctx context.Context, credentials *mtls.ConnectorProcessCredentials) (value.APIProcessObservation, mtls.ConnectorProcessObservation, error) {
	var zero value.APIProcessObservation
	if o == nil || credentials == nil || credentials != o.credentials {
		return zero, mtls.ConnectorProcessObservation{}, cfg.ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.finishing || !o.currentLocked(ctx) {
		return zero, mtls.ConnectorProcessObservation{}, cfg.ErrUnavailable
	}
	owned, err := credentials.ConfirmConnectorProcessAt(ctx, o.proof.owned, o.proof.source)
	until := identity.Earlier(o.proof.validUntil, owned.ValidUntil)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	process := value.APIProcessObservation{Binding: o.process.binding, CheckedAt: o.proof.observedAt, ValidUntil: until}
	if err != nil || !o.currentLocked(ctx) || !process.Valid(o.process.guard.attester.client.now()) {
		return zero, mtls.ConnectorProcessObservation{}, cfg.ErrUnavailable
	}
	owned.ValidUntil = until
	return process, owned, nil
}

func (o *connectorAPISetup) Source(ctx context.Context) (fleet.ConnectorIdentitySource, error) {
	if o == nil {
		return fleet.ConnectorIdentitySource{}, cfg.ErrUnavailable
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sourceUsed || o.finishing || o.finished || !o.currentLocked(ctx) {
		return fleet.ConnectorIdentitySource{}, cfg.ErrUnavailable
	}
	o.sourceUsed = true
	out := o.proof.source
	out.Observation.Profile = out.Observation.Profile.Clone()
	out.Observation.FreshUntil = identity.Earlier(out.Observation.FreshUntil, o.proof.validUntil)
	if d, ok := ctx.Deadline(); ok {
		out.Observation.FreshUntil = identity.Earlier(out.Observation.FreshUntil, d)
	}
	if !out.Valid(o.process.guard.attester.client.now()) || !o.currentLocked(ctx) {
		return fleet.ConnectorIdentitySource{}, cfg.ErrUnavailable
	}
	return out, nil
}

func (o *connectorAPISetup) Finish(ctx context.Context) error {
	if o == nil {
		return cfg.ErrUnavailable
	}
	o.mu.Lock()
	if !o.sourceUsed || o.finishing || o.finished || !o.currentLocked(ctx) {
		o.mu.Unlock()
		return cfg.ErrUnavailable
	}
	o.finishing = true
	o.joined.Add(1)
	p := o.proof
	o.mu.Unlock()
	defer o.joined.Done()
	until := p.validUntil
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(o.root, until)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancel(); close(done) })
	defer func() {
		cancel()
		if !stop() {
			<-done
		}
	}()
	checked, err := o.finishNative(call, p)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.finishing = false
	// Narrow before checking freshness, without hiding a producer that tried
	// to renew the original end. A deadline's timer may not have fired yet.
	renewed := checked.validUntil.After(p.validUntil)
	checked.validUntil = identity.Earlier(checked.validUntil, until)
	if err != nil || call.Err() != nil || !o.currentLocked(ctx) || checked.generation != p.generation || checked.observedAt != p.observedAt || renewed || !checked.valid(o.process.guard.attester.client.now()) {
		o.closed = true
		o.cancel()
		o.process.guard.reuse.invalidate()
		return cfg.ErrUnavailable
	}
	o.proof, o.finished = checked, true
	return nil
}

func (g *ConnectorAPIExecutionProtection) finishSetup(ctx context.Context, p connectorAPIProof) (connectorAPIProof, error) {
	if err := g.recheckNative(ctx, p); err != nil {
		return connectorAPIProof{}, err
	}
	source, err := g.attester.source.ReadConnectorIdentitySource(ctx)
	if err != nil || !source.Valid(g.attester.client.now()) || source.Roles != p.source.Roles || !source.Observation.SameSource(p.source.Observation) {
		return connectorAPIProof{}, cfg.ErrChanged
	}
	owned, err := g.credentials.ConfirmConnectorProcessAt(ctx, p.owned, source)
	if err != nil || owned.Request.Process != p.owned.Request.Process || owned.Registration != p.owned.Registration {
		return connectorAPIProof{}, cfg.ErrChanged
	}
	p.validUntil = identity.Earlier(p.validUntil, identity.Earlier(source.Observation.FreshUntil, owned.ValidUntil))
	p.source = source
	p.source.Observation.Profile = source.Observation.Profile.Clone()
	if ctx.Err() != nil || !p.valid(g.attester.client.now()) {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	return p, nil
}

func (o *connectorAPISetup) Close() {
	if o == nil {
		return
	}
	o.closeOnce.Do(func() {
		o.mu.Lock()
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		o.joined.Wait()
		if !o.stopParent() {
			<-o.parentDone
		}
	})
}
