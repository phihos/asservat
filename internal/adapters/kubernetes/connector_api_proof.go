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
	// ADR-251: the one background rebuild, separate from request flights so a
	// request holding a valid cached proof never waits on it. demanded records
	// a request read since that rebuild began; wake nudges the refresh loop.
	refresh       *connectorAPIProofFlight
	refreshCancel context.CancelFunc
	demanded      bool
	wake          chan struct{}
}

// ADR-251 constants. A proof lasts at most five seconds from its start and a
// rebuild takes about one to two, so a successor started with three seconds
// left arrives while its predecessor still has one to two.
const (
	connectorAPIProofRefreshBelow = 3 * time.Second
	connectorAPIProofRefreshLimit = 5 * time.Second
)

// Invalidation cannot be undone by an already running producer. Every failed
// current read uses this boundary, including an independently observed change.
// It also cancels a background rebuild, whose result could not enter anyway.
func (s *connectorAPIProofState) invalidate() {
	s.mu.Lock()
	s.invalidateLocked()
	s.mu.Unlock()
}
func (s *connectorAPIProofState) invalidateLocked() {
	s.generation++
	s.cached = nil
	if s.refreshCancel != nil {
		s.refreshCancel()
	}
}

// demand records a request's use of the cache: the refresh loop rebuilds a
// successor only for a proof that requests are still reading.
func (s *connectorAPIProofState) demand() {
	s.mu.Lock()
	s.demanded = true
	wake := s.wakeLocked()
	s.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}
func (s *connectorAPIProofState) wakeLocked() chan struct{} {
	if s.wake == nil {
		s.wake = make(chan struct{}, 1)
	}
	return s.wake
}

// refreshLoop keeps a fresh proof ready off the request path until ctx ends.
// One rebuild runs at a time, in this goroutine, only while the freshest
// cached proof has been read since the previous rebuild began and has less
// than below left. A rebuilt proof keeps its own original start and end; it
// never changes the proof it succeeds, which stays usable until its own end.
// Requests wait for a rebuild only when no valid proof is cached.
func (s *connectorAPIProofState) refreshLoop(ctx context.Context, now func() time.Time, below time.Duration, produce func(context.Context) (connectorAPIProof, error)) {
	s.mu.Lock()
	wake := s.wakeLocked()
	s.mu.Unlock()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for ctx.Err() == nil {
		s.mu.Lock()
		due, idle := time.Duration(0), true
		if c := s.cached; c != nil && s.demanded && s.refresh == nil && c.valid(now()) {
			due, idle = c.validUntil.Sub(now())-below, false
		}
		s.mu.Unlock()
		if idle || due > 0 {
			if !idle {
				timer.Reset(due)
			}
			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-timer.C:
			}
			timer.Stop()
			continue
		}
		s.rebuild(ctx, now, below, produce)
	}
}

func (s *connectorAPIProofState) rebuild(ctx context.Context, now func() time.Time, below time.Duration, produce func(context.Context) (connectorAPIProof, error)) {
	s.mu.Lock()
	c := s.cached
	if c == nil || !s.demanded || s.refresh != nil || !c.valid(now()) || c.validUntil.Sub(now()) > below {
		s.mu.Unlock()
		return
	}
	call, cancel := context.WithTimeout(ctx, connectorAPIProofRefreshLimit)
	defer cancel()
	f := &connectorAPIProofFlight{done: make(chan struct{}), generation: s.generation}
	s.refresh, s.refreshCancel, s.demanded = f, cancel, false
	s.mu.Unlock()
	p, err := produce(call)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || call.Err() != nil || s.generation != f.generation || !p.valid(now()) {
		// The same boundary as a request's own failed production: an error
		// may be a change, so no earlier proof stays usable.
		if s.generation == f.generation {
			s.invalidateLocked()
		}
		f.err = cfg.ErrUnavailable
		if err != nil {
			f.err = errors.Join(cfg.ErrUnavailable, err)
		}
	} else {
		f.result = p
		if s.cached == nil || p.validUntil.After(s.cached.validUntil) {
			copy := p
			s.cached = &copy
		}
	}
	s.refresh, s.refreshCancel = nil, nil
	close(f.done)
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

// The initiating caller owns producer/recheck execution synchronously. Waiters
// may cancel independently, but can neither detach a producer nor prolong its
// original interval. No goroutine or timer survives this call; the separate
// ADR-251 refresh loop is the only background producer.
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
	old := s.cached
	if old != nil && !old.valid(now()) {
		s.cached = nil
		old = nil
	}
	// Without a valid cached proof, join a current background rebuild rather
	// than start a second production.
	if f := s.refresh; old == nil && f != nil && f.generation == s.generation {
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
		s.invalidateLocked()
		// Still unavailable to every caller; the producer's fixed check stays
		// attached for the process's diagnostic line.
		f.err = cfg.ErrUnavailable
		if err != nil {
			f.err = errors.Join(cfg.ErrUnavailable, err)
		}
	} else {
		// A background rebuild may have cached a fresher proof meanwhile; a
		// recheck of the older one then narrows only this caller's copy.
		if c := s.cached; c == nil || c.observedAt.Equal(p.observedAt) || p.validUntil.After(c.validUntil) {
			copy := p
			s.cached = &copy
		}
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

// RefreshProofs runs the ADR-251 background rebuild until ctx ends; the caller
// joins it on shutdown. It adds no authority: each rebuilt proof is a complete
// ordinary production, and every reuse still performs its current recheck.
// report, if set, receives a fixed event and producer-owned timing text for
// each rebuild (never inputs or dependency error text).
func (g *ConnectorAPIExecutionProtection) RefreshProofs(ctx context.Context, report func(event, timing string)) {
	if g == nil || g.attester == nil || g.attester.client == nil || ctx == nil {
		return
	}
	produce := func(call context.Context) (connectorAPIProof, error) {
		started := time.Now()
		p, err := g.produceProof(call)
		if report != nil {
			event, timing := "rebuilt", "took "+time.Since(started).Round(10*time.Millisecond).String()+" left "+p.validUntil.Sub(g.attester.client.now()).Round(10*time.Millisecond).String()
			var step *connectorAPIStepError
			if errors.As(err, &step) {
				event, timing = "failed "+step.phase, step.step
			} else if err != nil {
				event = "failed"
			}
			report(event, timing)
		}
		return p, err
	}
	g.reuse.refreshLoop(ctx, g.attester.client.now, connectorAPIProofRefreshBelow, produce)
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
