package kubernetes

import (
	"context"
	"errors"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

// One positive proof for one concrete immutable protection instance. These are
// public provenance and original observation dates, never credentials or a new
// denial receipt. Expiry/current failure cannot fall back to an earlier proof.
type connectorAPIProof struct {
	proof                  fleet.ConnectorProcessProof
	owned                  mtls.ConnectorProcessObservation
	source                 fleet.ConnectorIdentitySource
	generation             uint64 // attached atomically with the returned proof
	observedAt, validUntil time.Time
}

func (p connectorAPIProof) valid(now time.Time) bool {
	return p.proof.Valid(now) && p.owned.Request.Process == p.proof.Process && identity.Fresh(p.observedAt, p.validUntil, now, 5*time.Second) && !p.validUntil.After(p.proof.FreshUntil) && !p.validUntil.After(p.owned.ValidUntil)
}

type connectorAPIProofFlight struct {
	done       chan struct{}
	generation uint64
	result     connectorAPIProof
	err        error
}
type connectorAPIProofState struct {
	mu         sync.Mutex
	generation uint64
	cached     *connectorAPIProof
	flight     *connectorAPIProofFlight
}

// Invalidation cannot be undone by an already running producer. Every failed
// current read uses this boundary, including an independently observed change.
func (s *connectorAPIProofState) invalidate() {
	s.mu.Lock()
	s.generation++
	s.cached = nil
	s.mu.Unlock()
}
func (s *connectorAPIProofState) finish(ctx context.Context, now func() time.Time, f *connectorAPIProofFlight) (connectorAPIProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := f.result
	if f.err != nil {
		return connectorAPIProof{}, f.err
	}
	if ctx.Err() != nil || s.generation != f.generation || !p.valid(now()) {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	if d, ok := ctx.Deadline(); ok {
		p.validUntil = identity.Earlier(p.validUntil, d)
	}
	if !p.valid(now()) {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	p.generation = f.generation
	return p, nil
}

// proofReuseMargin is the least remaining validity a cached proof needs to
// be reused rather than produced again.
const proofReuseMargin = 2 * time.Second

// The initiating caller owns producer/recheck execution synchronously. Waiters
// may cancel independently, but can neither detach a producer nor prolong its
// original interval. No goroutine, timer or refresh survives this call.
func (s *connectorAPIProofState) read(ctx context.Context, now func() time.Time, produce func(context.Context) (connectorAPIProof, error), recheck func(context.Context, connectorAPIProof) (connectorAPIProof, error)) (connectorAPIProof, error) {
	if ctx == nil || ctx.Err() != nil {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if f := s.flight; f != nil {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return connectorAPIProof{}, cfg.ErrUnavailable
		case <-f.done:
			return s.finish(ctx, now, f)
		}
	}
	f := &connectorAPIProofFlight{done: make(chan struct{}), generation: s.generation}
	s.flight = f
	old := s.cached
	// A proof near its end would pass reuse yet fail the caller's ADR-212
	// one-second headroom (installed native 41197238161: process@<0.5s).
	// Produce a fresh one instead; no interval is extended.
	if old != nil && !old.valid(now().Add(proofReuseMargin)) {
		s.cached = nil
		old = nil
	}
	s.mu.Unlock()
	var p connectorAPIProof
	var err error
	if old == nil {
		p, err = produce(ctx)
	} else {
		call, stop := context.WithDeadline(ctx, old.validUntil)
		p, err = recheck(call, *old)
		stop()
		// A recheck can shorten this exact snapshot, never replace its start,
		// identity or expiry with the time of the successful cheap read.
		if err == nil && (p.observedAt != old.observedAt || p.validUntil.After(old.validUntil) || p.proof.Process != old.proof.Process) {
			err = cfg.ErrChanged
		}
	}
	s.mu.Lock()
	if err != nil || ctx.Err() != nil || s.generation != f.generation || !p.valid(now()) {
		s.generation++
		s.cached = nil
		// Still unavailable to every caller; the producer's fixed check stays
		// attached for the process's diagnostic line.
		f.err = cfg.ErrUnavailable
		if err != nil {
			f.err = errors.Join(cfg.ErrUnavailable, err)
		}
	} else {
		copy := p
		s.cached = &copy
		f.result = p
	}
	s.flight = nil
	close(f.done)
	s.mu.Unlock()
	return s.finish(ctx, now, f)
}
func (g *ConnectorAPIExecutionProtection) current(ctx context.Context) (connectorAPIProof, error) {
	if g == nil || g.attester == nil || g.attester.client == nil || ctx == nil {
		return connectorAPIProof{}, cfg.ErrUnavailable
	}
	return g.reuse.read(ctx, g.attester.client.now, g.produceProof, g.recheckProof)
}

// Reuse only the expensive independent denial/TokenReview proof, under its
// unchanged original interval. Read the exact current owned process, source,
// full live workload, mounted input metadata, account, namespace and guard pins.
// A positive GET does not synthesize either original proof.
func (g *ConnectorAPIExecutionProtection) recheckProof(ctx context.Context, p connectorAPIProof) (connectorAPIProof, error) {
	fail := func(e error) (connectorAPIProof, error) { g.reuse.invalidate(); return connectorAPIProof{}, e }
	if ctx.Err() != nil || !p.valid(g.attester.client.now()) {
		return fail(cfg.ErrUnavailable)
	}
	owned, e := g.credentials.ObserveConnectorProcess(ctx)
	if e != nil || owned.Request.Process != p.owned.Request.Process || owned.Registration.Certificate != p.owned.Registration.Certificate || !owned.Configuration.SameSource(p.owned.Configuration) {
		return fail(cfg.ErrChanged)
	}
	p.validUntil = identity.Earlier(p.validUntil, owned.ValidUntil)
	call, stop := context.WithDeadline(ctx, p.validUntil)
	defer stop()
	if e := g.recheckNative(call, p); e != nil {
		return fail(e)
	}
	if call.Err() != nil || !p.valid(g.attester.client.now()) {
		return fail(cfg.ErrUnavailable)
	}
	return p, nil
}

// Native current-value checks shared by an ordinary recheck and the explicit
// setup close. Neither caller can replace the original denial/TokenReview
// interval. The setup close separately performs its full source proof and
// local owned-credential confirmation after this work.
func (g *ConnectorAPIExecutionProtection) recheckNative(call context.Context, p connectorAPIProof) error {
	ns, e := g.attester.client.namespace(call, g.attester.client.control)
	if e != nil || ns.Deleting {
		return cfg.ErrChanged
	}
	s := g.installed
	account, e := ownerResource[core.ServiceAccount](&OwnerEndpoints{client: g.attester.client}, call, "/api/v1/namespaces/"+s.Namespace+"/serviceaccounts/"+s.Account, "v1", "ServiceAccount")
	if e != nil || !ownerMetadata(account.ObjectMeta, s.Namespace, s.Account, s.AccountUID) {
		return cfg.ErrChanged
	}
	if e = g.executionAccount(call, p.proof); e != nil {
		return e
	}
	if _, e = checkAdmissionGuard(call, g.attester.client, g.attester.protection.plan.Name, g.attester.protection.pin, g.attester.protection.policy, g.attester.protection.binding); e != nil {
		return e
	}
	if _, e = checkAdmissionGuard(call, g.attester.client, g.settings.plan.Name, g.settings.pin, g.settings.policy, g.settings.binding); e != nil {
		return e
	}
	if e = g.snapshot(call); e != nil {
		return e
	}
	if e = g.workload(call, p.proof); e != nil {
		return e
	}
	if call.Err() != nil || !p.valid(g.attester.client.now()) {
		return cfg.ErrUnavailable
	}
	return nil
}
