package bootstrap

import (
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// The constructor is private to the fixed installed bootstrap composition.
// Its journal and source guard are actual adapters from the same deployment;
// no injected callback or retained native proof can supply either authority.
type providerCapacitySourceInvocation struct {
	observer  app.CapacitySourceObserver
	journal   *postgres.CapacitySourceJournal
	guard     *kube.CapacityGuard
	reader    *kube.InstalledWorkerProjectionReader
	claim     contracts.CapacityRuntimeProjectionClaim
	admission *fleetapp.WorkerRuntimeAdmission
}

func newProviderCapacitySourceInvocation(d *CapacityWorkerDeployment, reader *kube.InstalledWorkerProjectionReader, claim contracts.CapacityRuntimeProjectionClaim, worker contracts.HubWorkerDeployment, admission *fleetapp.WorkerRuntimeAdmission) (*providerCapacitySourceInvocation, error) {
	if d == nil || d.reconciler == nil || d.reconciler.Source == nil || d.reconciler.Work == nil || reader == nil || admission == nil || worker.Activation == nil || worker.Activation.WorkerLayout != contracts.HubWorkerProviderInstalledLayout || !capacityProjectionMatches(d.input, d.manifest, claim, worker) {
		return nil, mounts.ErrUnavailable
	}
	o := *d.reconciler.Source
	j, ok := o.Journal.(*postgres.CapacitySourceJournal)
	if !ok || j == nil || o.Recovery != j {
		return nil, mounts.ErrUnavailable
	}
	g, ok := o.Protection.(*kube.CapacityGuard)
	if !ok || g == nil {
		return nil, mounts.ErrUnavailable
	}
	q := d.reconciler.Work.Qualification
	if !q.Valid() || o.RootID != d.input.PermissionRootID || o.InstallationID != d.input.InstallationID || o.QualificationID != q.ID || o.QualificationDigest != q.Digest {
		return nil, mounts.ErrUnavailable
	}
	s := &providerCapacitySourceInvocation{observer: o, journal: j, guard: g, reader: reader, admission: admission}
	raw, err := json.Marshal(claim)
	if err != nil || json.Unmarshal(raw, &s.claim) != nil {
		return nil, mounts.ErrUnavailable
	}
	return s, nil
}

func (s *providerCapacitySourceInvocation) Observe(ctx context.Context) (app.AcceptedCapacitySource, error) {
	var zero app.AcceptedCapacitySource
	if s == nil || ctx == nil || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	lease, err := s.admission.WaitCapacity(ctx)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer lease.Release()
	// Every invocation owns fresh one-use state. The shared reconciler's
	// concrete observer and its actual adapters are never mutated.
	p := newProviderCapacitySourceOperation(lease.Context(), s)
	defer p.close()
	observer := s.observer
	observer.Protection, observer.Journal = p, p
	return observer.Observe(p.ctx)
}

type providerCapacitySourcePhase uint8

const (
	providerCapacityNew providerCapacitySourcePhase = iota
	providerCapacityReading
	providerCapacityRead
	providerCapacityProving
	providerCapacityProtected
	providerCapacityFinalizing
	providerCapacityAccepted
	providerCapacityFailed
	providerCapacityInvalidating
	providerCapacityInvalidated
)

type providerCapacitySourceContextKey struct{}

type providerCapacitySourceOperation struct {
	self      *providerCapacitySourceOperation
	owner     *providerCapacitySourceInvocation
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	phase     providerCapacitySourcePhase
	busy      bool
	closed    bool
	owners    sync.WaitGroup
	once      sync.Once
	until     time.Time
	recovery  artifact.RecoveryProof
	revision  int64
	proof     app.CapacitySourceProtection
	native    *kube.WorkerProjectionOperation
	nativeEnd context.CancelFunc
}

func newProviderCapacitySourceOperation(ctx context.Context, owner *providerCapacitySourceInvocation) *providerCapacitySourceOperation {
	p := &providerCapacitySourceOperation{owner: owner, revision: -1}
	p.self = p
	p.ctx, p.cancel = context.WithCancel(context.WithValue(ctx, providerCapacitySourceContextKey{}, p))
	return p
}

// A call must descend from this exact invocation. The earliest admitted child
// deadline is irreversible, including after a failed phase. Close admits no
// more calls and joins the actual adapter work before its FIFO ticket releases.
func (p *providerCapacitySourceOperation) enter(ctx context.Context, next providerCapacitySourcePhase, allowed ...providerCapacitySourcePhase) (context.Context, func(providerCapacitySourcePhase), error) {
	if p == nil || p.self != p || p.owner == nil || ctx == nil || ctx.Value(providerCapacitySourceContextKey{}) != p {
		return nil, nil, mounts.ErrUnavailable
	}
	p.mu.Lock()
	until, bounded := ctx.Deadline()
	if bounded && (p.until.IsZero() || until.Before(p.until)) {
		p.until = until
	}
	permitted := false
	for _, phase := range allowed {
		permitted = permitted || p.phase == phase
	}
	if !bounded || !permitted || p.closed || p.busy || ctx.Err() != nil || p.ctx.Err() != nil || !time.Now().Before(p.until) {
		p.mu.Unlock()
		return nil, nil, mounts.ErrUnavailable
	}
	p.phase, p.busy = next, true
	p.owners.Add(1)
	call, cancel := context.WithDeadline(ctx, p.until)
	p.mu.Unlock()
	joined := make(chan struct{})
	stop := context.AfterFunc(p.ctx, func() { cancel(); close(joined) })
	var once sync.Once
	done := func(phase providerCapacitySourcePhase) {
		once.Do(func() {
			cancel()
			if !stop() {
				<-joined
			}
			p.mu.Lock()
			p.phase, p.busy = phase, false
			p.mu.Unlock()
			p.owners.Done()
		})
	}
	return call, done, nil
}

func providerCapacitySameRecovery(a, b artifact.RecoveryProof) bool {
	return a.InstallationID == b.InstallationID && a.IssuerEpoch == b.IssuerEpoch && a.Revision == b.Revision && a.ObservedAt.Equal(b.ObservedAt) && a.FreshUntil.Equal(b.FreshUntil)
}

func (p *providerCapacitySourceOperation) ReadCapacitySourceRevision(ctx context.Context, r artifact.RecoveryProof) (int64, error) {
	call, done, err := p.enter(ctx, providerCapacityReading, providerCapacityNew)
	if err != nil {
		return 0, err
	}
	phase := providerCapacityFailed
	defer func() { done(phase) }()
	if !r.Valid(time.Now()) || r.InstallationID != p.owner.observer.InstallationID {
		return 0, mounts.ErrUnavailable
	}
	revision, err := p.owner.journal.ReadCapacitySourceRevision(call, r)
	if err != nil || call.Err() != nil || revision < 0 || revision >= 1<<60 || !r.Valid(time.Now()) {
		return 0, mounts.ErrUnavailable
	}
	p.mu.Lock()
	p.recovery, p.revision = r, revision
	p.mu.Unlock()
	phase = providerCapacityRead
	return revision, nil
}

func (p *providerCapacitySourceOperation) CapacityProtection(ctx context.Context) (app.CapacitySourceProtection, error) {
	var zero app.CapacitySourceProtection
	call, done, err := p.enter(ctx, providerCapacityProving, providerCapacityRead)
	if err != nil {
		return zero, err
	}
	phase := providerCapacityFailed
	defer func() { done(phase) }()
	nativeCall, err := p.retainNativeContext(ctx, call)
	if err != nil {
		return zero, err
	}
	op, claim, err := p.owner.reader.BeginCapacityProjectionOperation(nativeCall)
	if err != nil {
		return zero, err
	}
	p.mu.Lock()
	p.native = op
	p.mu.Unlock()
	if !reflect.DeepEqual(claim, p.owner.claim) {
		return zero, mounts.ErrUnavailable
	}
	call, end := context.WithDeadline(call, op.FreshUntil())
	defer end()
	// This is the original independently protected capacity source reader on
	// every successful invocation, never a result retained from Begin.
	proof, err := p.owner.guard.CapacityProtection(call)
	if err != nil || !proof.Valid(time.Now()) || call.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	proof.FreshUntil = identity.Earlier(proof.FreshUntil, op.FreshUntil())
	if !proof.Valid(time.Now()) {
		return zero, mounts.ErrUnavailable
	}
	p.mu.Lock()
	p.until = identity.Earlier(p.until, proof.FreshUntil)
	p.proof = proof
	p.mu.Unlock()
	phase = providerCapacityProtected
	return proof, nil
}

// Native Begin and Final bracket the whole observation, across journal phases.
// Keep the actual observer-call parent and the already admitted phase bound;
// returning from CapacityProtection must cancel its phase work without closing
// the retained bracket. This creates no observation or new authority interval.
func (p *providerCapacitySourceOperation) retainNativeContext(original, phase context.Context) (context.Context, error) {
	if p == nil || p.self != p || original == nil || phase == nil ||
		original.Value(providerCapacitySourceContextKey{}) != p || phase.Value(providerCapacitySourceContextKey{}) != p {
		return nil, mounts.ErrUnavailable
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	until, bounded := phase.Deadline()
	if !bounded || p.closed || !p.busy || p.phase != providerCapacityProving || p.nativeEnd != nil ||
		original.Err() != nil || phase.Err() != nil || p.ctx.Err() != nil || !time.Now().Before(p.until) {
		return nil, mounts.ErrUnavailable
	}
	until = identity.Earlier(until, p.until)
	call, cancel := context.WithDeadline(original, until)
	p.nativeEnd = cancel
	return call, nil
}

func (p *providerCapacitySourceOperation) invalidationBound(root string, revision int64, r artifact.RecoveryProof, observed, until time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return root == p.owner.observer.RootID && revision == p.revision && revision >= 0 && providerCapacitySameRecovery(r, p.recovery) && r.Valid(time.Now()) && !until.After(p.until) && identity.Fresh(observed, until, time.Now(), app.CapacitySourceInterval)
}

func (p *providerCapacitySourceOperation) InvalidateCapacitySource(ctx context.Context, root string, revision int64, r artifact.RecoveryProof, observed, until time.Time) error {
	call, done, err := p.enter(ctx, providerCapacityInvalidating, providerCapacityRead, providerCapacityFailed, providerCapacityProtected)
	if err != nil {
		return err
	}
	defer done(providerCapacityInvalidated)
	if !p.invalidationBound(root, revision, r, observed, until) {
		return mounts.ErrUnavailable
	}
	// Forward exactly the existing observer's original failed() CAS and dates.
	return p.owner.journal.InvalidateCapacitySource(call, root, revision, r, observed, until)
}

func (p *providerCapacitySourceOperation) AcceptCapacitySource(ctx context.Context, in app.CapacitySourceAcceptance) (app.AcceptedCapacitySource, error) {
	var zero app.AcceptedCapacitySource
	call, done, err := p.enter(ctx, providerCapacityFinalizing, providerCapacityProtected)
	if err != nil {
		return zero, err
	}
	// Acceptance is one-use even after an unknown SQL reply. No invalidation,
	// retry of Accept, or new CREATE is inferred from that uncertain result.
	defer done(providerCapacityAccepted)
	p.mu.Lock()
	op, recovery, revision, protection := p.native, p.recovery, p.revision, p.proof
	p.mu.Unlock()
	s := p.owner.observer
	if op == nil || !in.Valid(time.Now()) || in.RootID != s.RootID || in.InstallationID != s.InstallationID || in.QualificationID != s.QualificationID || in.QualificationDigest != s.QualificationDigest || in.ExpectedRevision != revision || !providerCapacitySameRecovery(in.Recovery, recovery) || !reflect.DeepEqual(in.Protection, protection) {
		return zero, mounts.ErrUnavailable
	}
	// The final native value pass precedes SQL acceptance. A failed final can
	// only fence the exact original revision and recovery, never create Ready
	// and then rely on a second transaction to retract it.
	if err = op.Finish(call); err != nil {
		until, _ := call.Deadline()
		observed := protection.ObservedAt
		if observed.Nanosecond()%1000 != 0 {
			observed = observed.Truncate(time.Microsecond).Add(time.Microsecond)
		}
		until = until.Truncate(time.Microsecond)
		if call.Err() == nil && p.invalidationBound(in.RootID, revision, recovery, observed, until) {
			_ = p.owner.journal.InvalidateCapacitySource(call, in.RootID, revision, recovery, observed, until)
		}
		return zero, mounts.ErrUnavailable
	}
	until := op.FreshUntil()
	if call.Err() != nil || !time.Now().Before(until) {
		return zero, mounts.ErrUnavailable
	}
	call, end := context.WithDeadline(call, until)
	defer end()
	// This exact transaction retains recovery/source/permission checks after
	// locks and narrows its commit context. No native I/O holds SQL locks.
	out, err := p.owner.journal.AcceptCapacitySource(call, in)
	if err != nil || call.Err() != nil || !time.Now().Before(until) {
		return zero, mounts.ErrUnavailable
	}
	return out, nil
}

func (p *providerCapacitySourceOperation) close() {
	if p == nil || p.self != p {
		return
	}
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.cancel()
		if p.nativeEnd != nil {
			p.nativeEnd()
		}
		p.mu.Unlock()
		p.owners.Wait()
		p.mu.Lock()
		op := p.native
		p.mu.Unlock()
		if op != nil {
			op.Close()
		}
	})
}
