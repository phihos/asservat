package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

// ContextNativeRuntimeConfig is installed composition, never public JSON.
// Owner is the actual serving process; its private Native router must exist.
// The first-preparation adapter closes the read/admission race in SQL. Neither
// this process nor the configuration contains a native reader or unwrap key.
type ContextNativeRuntimeConfig struct {
	Serving          ContextNativeServing
	Profile          value.DownloadWorkerProfile
	Configuration    WorkerConfigurationGuard
	Workers          ContextDownloadAttachments
	Preparation      FirstContextPreparationSessions
	Dispatcher       *DownloadDispatcher
	Sources          ContextDownloadSources
	Authority        CurrentDownloadAuthority
	Audit            auditapp.DownloadWriter
	Acknowledgements DownloadAuditAcknowledger
	Native           NativeAttachmentConfig
	Now              func() time.Time
	NewID            func() string
}
type ContextNativeServing interface {
	ContextNativeReady(context.Context) (time.Time, error)
}

// This marker is implemented by the purpose-specific atomic SQL adapter, not a
// caller-selectable public flag. Production bootstrap requires that concrete adapter.
type FirstContextPreparationSessions interface {
	DownloadSessions
	FirstContextPreparationOnly()
}
type ContextNativeRuntime struct {
	config   ContextNativeRuntimeConfig
	bound    *workerCurrentCheck
	metadata *contextNativeMetadata
	active   *contextNativeTransfers
}

type contextRuntimeAuthority struct{ check *workerCurrentCheck }

func (a contextRuntimeAuthority) CheckDownloadCurrent(ctx context.Context, _ identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	if a.check == nil || scope != a.check.scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	return a.check.Check(ctx)
}

var _ ContextDownloadRuntime = (*ContextNativeRuntime)(nil)

func NewContextNativeRuntime(c ContextNativeRuntimeConfig) (*ContextNativeRuntime, error) {
	if c.Serving == nil || !c.Profile.Valid() || c.Profile.StoreCredentialSecret == "" || c.Configuration == nil || c.Workers == nil || c.Preparation == nil || c.Dispatcher == nil || c.Dispatcher.Profile != c.Profile || c.Dispatcher.CurrentAuthority == nil || c.Dispatcher.Jobs == nil || c.Dispatcher.Ledger == nil || c.Dispatcher.Audit == nil || c.Dispatcher.Acknowledgements == nil || c.Sources == nil || c.Authority == nil || c.Audit == nil || c.Acknowledgements == nil || c.Now == nil || c.NewID == nil {
		return nil, artifact.ErrInvalid
	}
	n := c.Native
	if n.Enrollment != (value.WorkerEnrollment{}) || n.Registrar == nil || !value.UUID(n.HubPodUID) || !value.UUID(n.HubProcessEpoch) || !n.KeyScope.Valid() || n.KeyScope.InstallationID != c.Profile.InstallationID || n.KeyScope.Purpose != "artifact" || n.Owners == nil || n.Fences == nil || n.Origins.Operations == nil || n.Origins.Now == nil || n.PreparationKeys == nil || n.WindowKeys == nil {
		return nil, artifact.ErrInvalid
	}
	if _, ok := n.Owners.(interface{ FirstContextObservationsOnly() }); !ok {
		return nil, artifact.ErrInvalid
	}
	return &ContextNativeRuntime{config: c, metadata: newContextNativeMetadata(c.Now), active: newContextNativeTransfers()}, nil
}
func (r *ContextNativeRuntime) CheckContextDownloadRuntime(ctx context.Context, scope artifact.DownloadScope) (time.Time, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !scope.Valid() {
		return time.Time{}, artifact.ErrDownloadUnavailable
	}
	c := r.config
	original := c.Now().Add(artifact.DownloadLease)
	if d, ok := ctx.Deadline(); ok {
		original = identity.Earlier(original, d)
	}
	call, end := context.WithDeadline(ctx, original)
	defer end()
	serving, e := c.Serving.ContextNativeReady(call)
	if e != nil {
		return time.Time{}, stepped("serving", e)
	}
	until, e := c.Configuration.CurrentWorkerConfiguration(call, c.Profile)
	until = identity.Earlier(until, identity.Earlier(original, serving))
	if e != nil || call.Err() != nil || !c.Now().Before(until) {
		return time.Time{}, collapsed("worker-configuration", artifact.ErrDownloadUnavailable, e)
	}
	return until, nil
}

// Every callback remains under this actual request and the earliest observed
// deadline. Beginning another HTTP request is the only way to get another
// CurrentIdentity; polling cannot turn this closure into a renewable lease.
func (r *ContextNativeRuntime) beginRequest(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession) (*ContextNativeRuntime, context.Context, context.CancelFunc, artifact.DownloadAuthority, error) {
	return r.beginRequestAuthority(ctx, current, session, nil)
}

// Only an in-process coordinator can supply this already-checked short value.
// Direct runtime operations continue to reconstruct their complete authority.
func (r *ContextNativeRuntime) beginResponseRequest(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, a artifact.DownloadAuthority) (*ContextNativeRuntime, context.Context, context.CancelFunc, artifact.DownloadAuthority, error) {
	return r.beginRequestAuthority(ctx, current, session, &a)
}

func (r *ContextNativeRuntime) beginRequestAuthority(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, observed *artifact.DownloadAuthority) (*ContextNativeRuntime, context.Context, context.CancelFunc, artifact.DownloadAuthority, error) {
	var zero artifact.DownloadAuthority
	if r == nil || ctx == nil || ctx.Err() != nil || current == nil || !session.Valid() || session.StopProtocol != artifact.DownloadStopProtocol || session.State.Terminal() {
		return nil, nil, nil, zero, artifact.ErrDownloadUnavailable
	}
	call, end := context.WithDeadline(ctx, session.Deadline)
	var check *workerCurrentCheck
	var initial artifact.DownloadAuthority
	var e error
	if observed == nil {
		check, initial, e = newWorkerCurrentObservation(call, current, r.config.Authority, session.Scope, r.config.Now)
	} else {
		check, initial, e = newWorkerResponseObservation(call, current, *observed, session.Scope, r.config.Now)
	}
	if e != nil {
		end()
		return nil, nil, nil, zero, e
	}
	narrow, stop := context.WithDeadline(call, check.Deadline())
	c := r.config
	gate := contextRuntimeAuthority{check}
	c.Authority = gate
	dispatcher := *c.Dispatcher
	dispatcher.CurrentAuthority = gate
	c.Dispatcher = &dispatcher
	c.Native.Authority = gate
	return &ContextNativeRuntime{config: c, bound: check, metadata: r.metadata, active: r.active}, narrow, func() { stop(); end() }, initial, nil
}
func (r *ContextNativeRuntime) attachment(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession) (ContextDownloadAttachment, artifact.DownloadAuthority, error) {
	a, e := r.config.Authority.CheckDownloadCurrent(ctx, current, session.Scope)
	if e != nil {
		return ContextDownloadAttachment{}, a, artifact.ErrDownloadUnavailable
	}
	return r.attachmentWithAuthority(ctx, session, a)
}

// Every attachment read uses the operation's original authority observation and
// independently rereads SQL. Reclip this value after any narrower source bound
// without changing the original proof or repeating the human authorizer.
func (r *ContextNativeRuntime) attachmentWithAuthority(ctx context.Context, session artifact.DownloadSession, a artifact.DownloadAuthority) (ContextDownloadAttachment, artifact.DownloadAuthority, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ContextDownloadAttachment{}, a, artifact.ErrDownloadUnavailable
	}
	if r.bound != nil {
		until, e := r.bound.narrow(a.ValidUntil)
		if e != nil {
			return ContextDownloadAttachment{}, a, artifact.ErrDownloadUnavailable
		}
		a.ValidUntil = until
	}
	if ctx.Err() != nil || !a.Valid(r.config.Now()) || a.Scope != session.Scope || !a.Environment.CurrentValid(r.config.Now()) || a.Environment.Path.AcquisitionClusterID != r.config.Profile.ClusterID || a.Environment.Path.WorkerConfiguration != r.config.Profile.Configuration {
		return ContextDownloadAttachment{}, a, artifact.ErrDownloadUnavailable
	}
	call, end := context.WithDeadline(ctx, a.ValidUntil)
	defer end()
	found, e := r.config.Workers.ReadContextDownloadAttachment(call, session.ID, a)
	if e != nil || !found.Valid(r.config.Now()) || found.Scope != session.Scope || call.Err() != nil {
		return ContextDownloadAttachment{}, a, artifact.ErrDownloadUnavailable
	}
	if r.bound != nil {
		until, e := r.bound.narrow(found.ValidUntil)
		if e != nil {
			return ContextDownloadAttachment{}, a, e
		}
		a.ValidUntil = identity.Earlier(a.ValidUntil, until)
	}
	return found, a, nil
}
func (r *ContextNativeRuntime) native(en value.WorkerEnrollment) (*NativeAttachment, error) {
	c := r.config.Native
	c.Enrollment = en
	c.Authority = r.config.Authority
	c.Now = r.config.Now
	c.NewID = r.config.NewID
	return NewNativeAttachment(c)
}
func (r *ContextNativeRuntime) ContinueContextDownload(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, source ContextDownloadSource) (ContextDownloadContinuation, error) {
	return r.continueContextDownloadAuthority(ctx, current, session, source, nil)
}

func (r *ContextNativeRuntime) continueContextDownloadAuthority(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, source ContextDownloadSource, handoff *artifact.DownloadAuthority) (ContextDownloadContinuation, error) {
	var zero ContextDownloadContinuation
	bound, call, end, initial, e := r.beginRequestAuthority(ctx, current, session, handoff)
	if e != nil {
		return zero, stepped("runtime-authority", e)
	}
	defer end()
	r = bound
	shorten, finish := workerEffectContext(&call, r.bound.Deadline)
	defer finish()
	if session.State != artifact.DownloadPreparing || !source.Valid(r.config.Now()) || source.Scope != session.Scope {
		return zero, collapsed("source", artifact.ErrDownloadUnavailable, nil)
	}
	if _, e = r.bound.narrow(source.ValidUntil); e != nil {
		return zero, stepped("source-bound", e)
	}
	shorten()
	observed, _, e := r.attachmentWithAuthority(call, session, initial)
	if e != nil {
		return zero, stepped("attachment", e)
	}
	if observed.MetadataAttempted {
		if observed.Preparation != nil {
			return zero, nil
		}
		return zero, collapsed("metadata-attempted", ErrDownloadMetadataUnavailable, nil)
	}
	intent := r.config.NewID()
	if observed.Found {
		intent = observed.Intent.ID
	}
	shorten()
	var worker value.DownloadWorker
	active := activeContextEnrollment(observed, r.config.Now(), r.bound.Deadline())
	if observed.Worker != nil {
		original := observed
		if active {
			// Keep exact values across the independently blocking current read.
			w, en, peer := *observed.Worker, *observed.Enrollment, *observed.ActivatedPeer
			original.Worker, original.Enrollment, original.ActivatedPeer = &w, &en, &peer
		}
		observed, e = r.observeBoundWorker(call, current, session, original)
		e = stepped("worker-observe", e)
		if e == nil {
			worker = *observed.Worker
			if active && (!sameActiveContextEnrollment(original, observed) || !activeContextEnrollment(observed, r.config.Now(), r.bound.Deadline())) {
				return zero, collapsed("enrollment-changed", artifact.ErrDownloadUnavailable, nil)
			}
		}
	} else {
		worker, e = r.config.Dispatcher.ensureChecked(call, session.ID, intent, session.Scope, r.bound.Check, r.bound.Deadline)
		e = stepped("dispatch", e)
	}
	if e != nil {
		var pending *DownloadWorkerPending
		if errors.As(e, &pending) && pending.Valid(r.config.Now()) && pending.Intent.ID == intent && pending.Intent.SessionID == session.ID && pending.Intent.Authority.Scope == session.Scope {
			return ContextDownloadContinuation{Pending: true}, nil
		}
		return zero, e
	}
	if !active {
		// Enrollment belongs to the admitted worker's finite HTTP request.
		// Public preparation neither publishes a human owner nor waits for a
		// certificate. A later deliberate continuation observes the same
		// immutable worker and activated certificate under current authority.
		if call.Err() != nil || !r.config.Now().Before(r.bound.Deadline()) || !worker.Valid() {
			return zero, collapsed("enrollment-wait", artifact.ErrDownloadExpired, call.Err())
		}
		return ContextDownloadContinuation{Pending: true}, nil
	}

	shorten()
	native, e := r.native(*observed.Enrollment)
	if e != nil {
		return zero, stepped("native", e)
	}
	preparation := ContextDownloadWorker{Sessions: r.config.Preparation, AuditAcknowledgements: r.config.Acknowledgements, Audit: r.config.Audit, CurrentAuthority: r.config.Authority, RegionalPreparation: native, Now: r.config.Now, NewID: r.config.NewID}
	var retained *artifact.PreparedDownload
	m, e := preparation.prepareCurrentRetained(call, current, ContextDownloadRequest{SessionID: session.ID, Scope: session.Scope, Expectation: source.Expectation, Copies: source.Copies}, func(p artifact.PreparedDownload) error {
		retained = &p
		return nil
	})
	if e == nil && retained != nil {
		// The same request's Ready view would otherwise need a second worker
		// Observe conversation within this original bound (native20). Hand off
		// only the exact facts this acknowledged preparation returned.
		p := *retained
		p.Native.ReadUntil, p.Native.DeleteBy = m.ReadUntil, m.DeleteBy
		if p.Native == m {
			r.metadata.handoff(p)
		}
	}
	return zero, stepped("prepare", e)
}

// A bound worker has already completed launch admission, acknowledged intent,
// exact Job recording and Pod binding. Replaying those writes adds no current
// protection. Observe the original live Job/Pod, then independently reread SQL
// under fresh ordinary authority; neither stored binding nor the Pod alone is
// enough. Unbound and uncertain launch results keep ensureChecked's recovery.
func (r *ContextNativeRuntime) observeBoundWorker(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, original ContextDownloadAttachment) (ContextDownloadAttachment, error) {
	var zero ContextDownloadAttachment
	if r == nil || r.bound == nil || r.config.Dispatcher.Jobs == nil || !original.Valid(r.config.Now()) || original.Worker == nil || original.State != artifact.DownloadPreparing || original.NativeBusy || original.ResponseBusy || original.NativeUncertain {
		return zero, artifact.ErrDownloadUnavailable
	}
	worker := *original.Worker
	if worker.Intent.Profile != r.config.Profile || worker.Intent.SessionID != session.ID || worker.Intent.Authority.Scope != session.Scope {
		return zero, artifact.ErrDownloadUnavailable
	}
	until := identity.Earlier(r.bound.Deadline(), identity.Earlier(original.ValidUntil, worker.Intent.RunUntil))
	call, end := context.WithDeadline(ctx, until)
	defer end()
	observed, e := r.config.Dispatcher.Jobs.ObserveDownloadWorker(call, worker.Intent, worker.Job)
	if e != nil || observed != worker || !r.config.Now().Before(until) || call.Err() != nil {
		// Once bound, missing/changed/pending Pods cannot justify another launch
		// or an acknowledged startup continuation from the historical binding.
		return zero, artifact.ErrDownloadUnavailable
	}
	latest, _, e := r.attachment(call, current, session)
	if e != nil || latest.Worker == nil || *latest.Worker != worker || latest.State != artifact.DownloadPreparing || latest.NativeBusy || latest.ResponseBusy || latest.NativeUncertain {
		return zero, artifact.ErrDownloadUnavailable
	}
	// SQL may have consumed the original interval or observed cancellation.
	// Validate that local bound before any registration or preparation effect.
	if _, e = r.bound.Check(call); e != nil {
		return zero, e
	}
	return latest, nil
}

// This observation only avoids an enrollment route that cannot be needed during
// the original request. Native admission still proves the actual current peer.
// Match the credential supervisor's actual second-precision leaf renewal
// boundary. The period helper alone retains fractional original CreatedAt and
// can select the old epoch at that scheduling boundary.
func activeContextEnrollment(a ContextDownloadAttachment, now, until time.Time) bool {
	if !a.Valid(now) || a.Worker == nil || a.Enrollment == nil || a.ActivatedPeer == nil || a.MetadataAttempted || a.State != artifact.DownloadPreparing || a.NativeBusy || a.ResponseBusy || a.NativeUncertain || !now.Before(until) || until.After(a.ValidUntil) || until.After(a.ActivatedPeer.NotAfter) {
		return false
	}
	if a.ActivatedPeer.NotAfter.Equal(a.Worker.Intent.RunUntil.UTC().Truncate(time.Second)) {
		return true // The existing supervisor never renews its final period.
	}
	if !until.Before(a.ActivatedPeer.NotAfter.Add(-value.WorkerCertificateRenewBefore)) {
		return false
	}
	_, neededUntil, err := value.WorkerCertificateEpoch(*a.Worker, until)
	return err == nil && a.ActivatedPeer.NotAfter.Equal(neededUntil)
}

func sameActiveContextEnrollment(a, b ContextDownloadAttachment) bool {
	return a.Worker != nil && b.Worker != nil && *a.Worker == *b.Worker && a.Enrollment != nil && b.Enrollment != nil && *a.Enrollment == *b.Enrollment && a.ActivatedPeer != nil && b.ActivatedPeer != nil && *a.ActivatedPeer == *b.ActivatedPeer
}

func (r *ContextNativeRuntime) ReadPreparedContextDownload(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession) (artifact.PreparedDownload, bool, error) {
	out, _, release, e := r.prepared(ctx, current, session, false)
	if release != nil {
		release()
	}
	if e != nil {
		return artifact.PreparedDownload{}, false, e
	}
	return out, out.Preparation.Valid(), nil
}

// Cache misses may observe the already committed original result, never prepare
// it again. SQL and the original operation's local deadline/cancellation checks
// also run on warm hits and after waiting for another caller's joined load.
func (r *ContextNativeRuntime) prepared(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, pin bool) (artifact.PreparedDownload, contextNativeMetadataKey, func(), error) {
	return r.preparedAuthority(ctx, current, session, pin, nil)
}
func (r *ContextNativeRuntime) preparedAuthority(ctx context.Context, current identities.CurrentIdentity, session artifact.DownloadSession, pin bool, handoff *artifact.DownloadAuthority) (artifact.PreparedDownload, contextNativeMetadataKey, func(), error) {
	var zero artifact.PreparedDownload
	var key contextNativeMetadataKey
	bound, call, end, initial, e := r.beginRequestAuthority(ctx, current, session, handoff)
	if e != nil {
		return zero, key, nil, e
	}
	defer end()
	r = bound
	shorten, finish := workerEffectContext(&call, r.bound.Deadline)
	defer finish()
	observed, a, e := r.attachmentWithAuthority(call, session, initial)
	if e != nil {
		return zero, key, nil, e
	}
	if !observed.MetadataAttempted {
		return zero, key, nil, nil
	}
	if observed.Preparation == nil || observed.Enrollment == nil {
		return zero, key, nil, ErrDownloadMetadataUnavailable
	}
	key, e = contextMetadataKey(session, observed, a)
	if e != nil {
		return zero, key, nil, e
	}
	shorten()
	mayObserve := !observed.NativeBusy && !observed.ResponseBusy && observed.NativeTransitions >= 5 && observed.ActivatedPeer != nil
	facts, release, e := r.metadata.get(call, key, mayObserve, pin, func(load context.Context) (artifact.NativeDownloadMetadata, error) {
		if facts, ok := r.metadata.takeHandoff(key); ok {
			return facts, nil
		}
		remote, e := r.remote(load, session, observed, a)
		if e != nil {
			return artifact.NativeDownloadMetadata{}, e
		}
		defer remote.Close()
		// remote() may have learned a stricter original source bound.
		effect, stop := context.WithDeadline(load, r.bound.Deadline())
		defer stop()
		facts, _, e := remote.DescribeCurrent(effect, current, session, a)
		return facts, e
	})
	if e != nil {
		return zero, key, nil, e
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	shorten()
	latest, authority, e := r.attachment(call, current, session)
	if e != nil {
		return zero, key, nil, e
	}
	finalKey, e := contextMetadataKey(session, latest, authority)
	if e != nil || finalKey != key || (pin && (latest.NativeBusy || latest.ResponseBusy)) || latest.NativeUncertain || ((latest.NativeBusy || latest.ResponseBusy) && latest.State != artifact.DownloadStreaming) || (!latest.NativeBusy && !latest.ResponseBusy && latest.NativeTransitions < 3) || call.Err() != nil {
		return zero, key, nil, ErrDownloadMetadataUnavailable
	}
	// Never lengthen original retained facts after a later current check. These
	// bounds are projected again by the public coordinator before disclosure.
	facts.ReadUntil = identity.Earlier(facts.ReadUntil, authority.AccessUntil)
	facts.DeleteBy = identity.Earlier(facts.DeleteBy, authority.DeleteBy)
	if !r.config.Now().Before(facts.ReadUntil) || !facts.ReadUntil.Before(facts.DeleteBy) {
		return zero, key, nil, artifact.ErrDownloadExpired
	}
	out := artifact.PreparedDownload{Preparation: *latest.Preparation, Scope: session.Scope, Native: facts}
	success = true
	return out, key, release, nil
}

// Close cancels and joins registered HTTP work before releasing metadata.
// Private enrollment/request owners remain separately joined by their owner.
func (r *ContextNativeRuntime) Close() {
	if r != nil {
		r.active.close()
		r.metadata.close()
	}
}
func (r *ContextNativeRuntime) remote(ctx context.Context, session artifact.DownloadSession, observed ContextDownloadAttachment, a artifact.DownloadAuthority) (*RemoteContextSource, error) {
	if observed.Enrollment == nil || observed.Preparation == nil {
		return nil, ErrDownloadMetadataUnavailable
	}
	source, e := r.config.Sources.ReadContextDownloadSource(ctx, a)
	if e != nil || !source.Valid(r.config.Now()) || source.Scope != session.Scope {
		return nil, artifact.ErrDownloadUnavailable
	}
	if r.bound != nil {
		if _, e = r.bound.narrow(source.ValidUntil); e != nil {
			return nil, e
		}
	}
	native, e := r.native(*observed.Enrollment)
	if e != nil {
		return nil, e
	}
	// This constructor retains only immutable copies/expectation/preparation. Its
	// actual Describe/Read use fresh current callbacks and peer proof at each hop.
	return NewRemoteContextSource(ctx, native, ContextDownloadRequest{SessionID: session.ID, Scope: session.Scope, Expectation: source.Expectation, Copies: source.Copies}, *observed.Preparation)
}
