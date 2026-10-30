package evidence

import (
	"context"
	"slices"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextDownloadResultConfig is private acquisition-process composition. The
// exact admitted enrollment and process lifetime must come from protected
// startup, never a capture caller. This constructor proves no key possession,
// dispatch, certificate activation or remote native-work channel by itself.
type ContextDownloadResultConfig struct {
	Enrollment   value.WorkerEnrollment
	Worker       ContextDownloadWorker
	Proofs       WorkerEnrollmentProofReader
	Observations ContextDownloadControlLedger
	Request      ContextDownloadRequest
}

// ContextDownloadResultOwner retains one bounded verified metadata result for
// one original worker/process and session. It is neither a payload/key cache nor
// a queue. Its owning process may not be replaced after uncertain work. Closing
// cancels active calls; Wait joins them before the caller releases process slots.
type ContextDownloadResultOwner struct {
	mu                           sync.Mutex
	ctx                          context.Context
	cancel                       context.CancelFunc
	config                       ContextDownloadResultConfig
	until                        time.Time
	expiry                       *time.Timer
	attempted, preparing, closed bool
	active                       int
	done                         chan struct{}
	doneClosed                   bool
	result                       *artifact.PreparedDownload
}

type ContextDownloadResultObservation struct {
	Prepared   artifact.PreparedDownload
	ValidUntil time.Time
}

func NewContextDownloadResultOwner(parent context.Context, c ContextDownloadResultConfig) (*ContextDownloadResultOwner, error) {
	if parent == nil || parent.Err() != nil || !c.Enrollment.Valid() || c.Worker.CurrentAuthority == nil || c.Proofs == nil || c.Observations == nil || !c.Worker.valid(c.Request) || c.Request.SessionID != c.Enrollment.Worker.Intent.SessionID || c.Request.Scope != c.Enrollment.Worker.Intent.Authority.Scope {
		return nil, artifact.ErrInvalid
	}
	now := c.Worker.Now()
	until := identity.Earlier(c.Enrollment.Worker.Intent.RunUntil, c.Request.Expectation.Registration.ExpiresAt)
	if d, ok := parent.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if now.Before(c.Enrollment.Worker.Intent.CreatedAt) || !now.Before(until) {
		return nil, artifact.ErrDownloadExpired
	}
	// Caller-owned slices cannot retarget verification after construction.
	c.Request.Expectation.Audience = slices.Clone(c.Request.Expectation.Audience)
	c.Request.Expectation.RetentionRules = slices.Clone(c.Request.Expectation.RetentionRules)
	c.Request.Expectation.SourceSnapshotManifest = c.Request.Expectation.SourceSnapshotManifest.Clone()
	ctx, cancel := context.WithDeadline(parent, until)
	o := &ContextDownloadResultOwner{ctx: ctx, cancel: cancel, config: c, until: until, done: make(chan struct{})}
	context.AfterFunc(ctx, o.Close)
	return o, nil
}

func (o *ContextDownloadResultOwner) closeLocked() {
	if !o.closed {
		o.closed = true
		o.result = nil
		o.cancel()
		if o.expiry != nil {
			o.expiry.Stop()
		}
	}
	if o.active == 0 && !o.doneClosed {
		// Drop retained source/principal/backend references only after active
		// calls have left. This is lifetime control, not a Go heap-erasure claim.
		o.config = ContextDownloadResultConfig{}
		close(o.done)
		o.doneClosed = true
	}
}
func (o *ContextDownloadResultOwner) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeLocked()
}
func (o *ContextDownloadResultOwner) Wait(ctx context.Context) error {
	if o == nil || ctx == nil {
		return artifact.ErrInvalid
	}
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (o *ContextDownloadResultOwner) enter(ctx context.Context) (context.Context, func(), error) {
	if o == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	o.mu.Lock()
	if o.closed || o.ctx.Err() != nil || !o.config.Worker.Now().Before(o.until) {
		o.closeLocked()
		o.mu.Unlock()
		return nil, nil, artifact.ErrDownloadUnavailable
	}
	// The original acquisition process has one native operation and at most
	// one overlapping status request; transport admission may narrow this.
	if o.active >= 2 {
		o.mu.Unlock()
		return nil, nil, artifact.ErrDownloadCapacity
	}
	o.active++
	until := o.until
	o.mu.Unlock()
	call, cancel := context.WithDeadline(ctx, until)
	stop := context.AfterFunc(o.ctx, cancel)
	return call, func() {
		stop()
		cancel()
		o.mu.Lock()
		defer o.mu.Unlock()
		o.active--
		if o.closed {
			o.closeLocked()
		}
	}, nil
}
func (o *ContextDownloadResultOwner) shorten(until time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.ctx.Err() != nil || !o.config.Worker.Now().Before(until) {
		o.closeLocked()
		return artifact.ErrDownloadExpired
	}
	if until.Before(o.until) {
		o.until = until
		if o.expiry != nil {
			o.expiry.Stop()
		}
		o.expiry = time.AfterFunc(time.Until(until), o.Close)
	}
	return nil
}

// checked pins each call's current human identity and original response bound,
// then rechecks the exact admitted worker/process key through the existing live
// proof port. A token/Pod observation never supplies human permissions.
func (o *ContextDownloadResultOwner) checked(ctx context.Context, current identities.CurrentIdentity) (contextDownloadCheck, error) {
	check, err := o.config.Worker.identityCheck(ctx, current, o.config.Request)
	if err != nil {
		return nil, err
	}
	until := o.config.Worker.Now().Add(artifact.DownloadLease)
	return func(call context.Context) (artifact.DownloadAuthority, error) {
		a, err := check(call)
		if err != nil {
			return a, err
		}
		// Every observed restrictive access cutoff limits retained facts, even
		// if the subsequent proof or first response fails.
		if err = o.shorten(a.AccessUntil); err != nil {
			return artifact.DownloadAuthority{}, err
		}
		until = identity.Earlier(until, a.ValidUntil)
		proofCtx, stop := context.WithDeadline(call, until)
		e := o.config.Enrollment
		if a.Environment.InstallationID != e.Worker.Binding.InstallationID {
			stop()
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		proof, err := o.config.Proofs.ReadWorkerEnrollmentProof(proofCtx, e.Worker.Intent.SessionID, e.Worker.Intent.ID, e.PublicKeyDigest)
		proofErr := proofCtx.Err()
		stop()
		if err != nil || proofErr != nil || !proof.Valid(o.config.Worker.Now()) || proof.Worker != e.Worker || proof.PublicKeyDigest != e.PublicKeyDigest {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		a, err = check(call)
		if err != nil {
			return a, err
		}
		if err = o.shorten(a.AccessUntil); err != nil {
			return artifact.DownloadAuthority{}, err
		}
		if !proof.Valid(o.config.Worker.Now()) || a.Environment.InstallationID != e.Worker.Binding.InstallationID {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
		}
		until = identity.Earlier(until, identity.Earlier(proof.FreshUntil, a.ValidUntil))
		a.ValidUntil = until
		if !a.Valid(o.config.Worker.Now()) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
		}
		return a, nil
	}, nil
}

// Prepare performs at most one native preparation in this process owner. Later
// calls only read the exact retained result under fresh authority. A lost/failed
// begin or outcome acknowledgement remains uncertain and cannot create another
// batch/read. Restarted-owner preflight rejects already-spent SQL state; this
// local guard does not establish distributed process uniqueness or authority.
func (o *ContextDownloadResultOwner) Prepare(ctx context.Context, current identities.CurrentIdentity) error {
	call, leave, err := o.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	check, err := o.checked(call, current)
	if err != nil {
		return err
	}
	a, err := check(call)
	if err != nil {
		return err
	}
	r := o.config.Request
	observed, err := o.config.Observations.ObserveDownload(call, r.SessionID, a, nil)
	if err != nil || !observed.Valid(o.config.Worker.Now()) || observed.Session.Scope != r.Scope || observed.Session.ID != r.SessionID {
		return artifact.ErrDownloadUnavailable
	}
	if err = o.shorten(identity.Earlier(observed.Session.Deadline, a.AccessUntil)); err != nil {
		return err
	}
	o.mu.Lock()
	if o.closed || call.Err() != nil {
		o.mu.Unlock()
		return artifact.ErrDownloadUnavailable
	}
	if o.preparing {
		o.mu.Unlock()
		return artifact.ErrDownloadConflict
	}
	if o.result != nil {
		o.mu.Unlock()
		_, err = o.readChecked(call, check)
		return err
	}
	if o.attempted || observed.Session.State != artifact.DownloadPreparing || observed.Session.Generation != 0 || observed.Session.Requests != 0 || observed.Session.Active != nil {
		o.mu.Unlock()
		return ErrDownloadMetadataUnavailable
	}
	o.attempted = true
	o.preparing = true
	until := identity.Earlier(o.until, identity.Earlier(observed.ValidUntil, a.ValidUntil))
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.preparing = false; o.mu.Unlock() }()
	work, cancel := context.WithDeadline(call, until)
	defer cancel()
	_, err = o.config.Worker.prepareChecked(work, r, check, o.retain)
	return err
}

// retain is called only after the exact successful outcome acknowledgement. It
// deliberately does not consume an expired first-response observation. Retaining
// immutable facts is not evidence disclosure; Read must obtain fresh authority.
func (o *ContextDownloadResultOwner) retain(p artifact.PreparedDownload) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.ctx.Err() != nil || !o.config.Worker.Now().Before(o.until) {
		o.closeLocked()
		return artifact.ErrDownloadExpired
	}
	if !o.preparing || !o.attempted || o.result != nil || !p.Valid() || p.Scope != o.config.Request.Scope || p.Preparation.SessionID != o.config.Request.SessionID {
		return artifact.ErrIntegrity
	}
	o.result = &p
	return nil
}

func (o *ContextDownloadResultOwner) Read(ctx context.Context, current identities.CurrentIdentity) (ContextDownloadResultObservation, error) {
	call, leave, err := o.enter(ctx)
	if err != nil {
		return ContextDownloadResultObservation{}, err
	}
	defer leave()
	check, err := o.checked(call, current)
	if err != nil {
		return ContextDownloadResultObservation{}, err
	}
	return o.readChecked(call, check)
}
func (o *ContextDownloadResultOwner) readChecked(ctx context.Context, check contextDownloadCheck) (ContextDownloadResultObservation, error) {
	var zero ContextDownloadResultObservation
	a, err := check(ctx)
	if err != nil {
		return zero, err
	}
	o.mu.Lock()
	if o.closed || o.ctx.Err() != nil || !o.config.Worker.Now().Before(o.until) {
		o.closeLocked()
		o.mu.Unlock()
		return zero, artifact.ErrDownloadUnavailable
	}
	if o.result == nil {
		o.mu.Unlock()
		return zero, ErrDownloadMetadataUnavailable
	}
	p := *o.result
	until := identity.Earlier(o.until, a.ValidUntil)
	o.mu.Unlock()
	observed, err := o.config.Observations.ObserveDownload(ctx, p.Preparation.SessionID, a, &p.Preparation)
	if err != nil || !observed.Valid(o.config.Worker.Now()) || observed.Session.Scope != p.Scope || observed.Session.ID != p.Preparation.SessionID || observed.Session.ObservedState(o.config.Worker.Now()).Terminal() {
		return zero, artifact.ErrDownloadUnavailable
	}
	switch observed.Session.State {
	case artifact.DownloadReady, artifact.DownloadStreaming, artifact.DownloadInterrupted:
	default:
		return zero, artifact.ErrDownloadUnavailable
	}
	a, err = check(ctx)
	if err != nil {
		return zero, err
	}
	if err = o.shorten(identity.Earlier(observed.Session.Deadline, a.AccessUntil)); err != nil {
		return zero, err
	}
	until = identity.Earlier(until, identity.Earlier(observed.ValidUntil, a.ValidUntil))
	until = identity.Earlier(until, identity.Earlier(observed.Session.Deadline, a.AccessUntil))
	o.mu.Lock()
	defer o.mu.Unlock()
	until = identity.Earlier(until, o.until)
	if o.closed || o.ctx.Err() != nil || ctx.Err() != nil || !o.config.Worker.Now().Before(until) {
		return zero, artifact.ErrDownloadUnavailable
	}
	// No cached date or observation is reused as a current privacy decision.
	p.Native.ReadUntil = a.AccessUntil
	p.Native.DeleteBy = a.DeleteBy
	return ContextDownloadResultObservation{Prepared: p, ValidUntil: until}, nil
}
