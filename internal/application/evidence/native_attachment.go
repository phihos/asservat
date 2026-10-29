package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"sync"
	"time"
)

type NativeExchange interface {
	NativePreparationCommit
	Prepared(context.Context) (artifact.NativeDownloadMetadata, error)
	ReadChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error)
	AcknowledgeNativeChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) error
}
type NativePendingExchange interface {
	Wait(context.Context) (NativeExchange, error)
	Close()
}
type NativeProjectionExchange interface {
	Projection(context.Context) (query.PodStatusProjection, error)
	AcknowledgeProjection(context.Context) error
}

type NativeExchangeRegistration struct {
	Operation  value.NativeOperation
	Projection *query.ContextProjectionScope
	Source     NativeContextSource
	Delivery   artifact.DownloadDeliveryLease
	Complete   NativeCompletion
}

// The local registrar retains callbacks in the original hub process only.
// Before runs after real peer/Pod/SQL origin verification and before commands;
// Check remains live around each private frame and never serializes identity.
type NativeExchangeRegistrar interface {
	RegisterNativeExchange(context.Context, NativeExchangeRegistration, func(context.Context, NativeOrigin) error, func(context.Context, NativeOrigin) (value.NativeLease, error)) (NativePendingExchange, error)
}
type NativeFenceReader interface {
	NextNativeFence(context.Context, string) (int64, error)
}
type NativeWindowKeyBindings interface {
	BindNativeDownloadKeys(context.Context, value.NativeReference, artifact.DownloadDeliveryLease, value.KeyScope, value.KeyPeer, value.KeyWorkerProof) error
}
type NativeAttachmentConfig struct {
	Enrollment                 value.WorkerEnrollment
	HubPodUID, HubProcessEpoch string
	KeyScope                   value.KeyScope
	Owners                     NativeOperations
	Fences                     NativeFenceReader
	Origins                    NativeOrigins
	Registrar                  NativeExchangeRegistrar
	PreparationKeys            DownloadKeyBindingLedger
	WindowKeys                 NativeWindowKeyBindings
	Authority                  CurrentDownloadAuthority
	Now                        func() time.Time
	NewID                      func() string
}

// NativeAttachment contains no bearer, raw storage reader, unwrap key or SQL
// bootstrap authority. All operations bind a live original human request and
// the already admitted worker/process. Its presence alone starts no work.
type NativeAttachment struct{ config NativeAttachmentConfig }

func NewNativeAttachment(c NativeAttachmentConfig) (*NativeAttachment, error) {
	if !c.Enrollment.Valid() || !value.UUID(c.HubPodUID) || !value.UUID(c.HubProcessEpoch) || !c.KeyScope.Valid() || c.KeyScope.Purpose != "artifact" || c.KeyScope.InstallationID != c.Enrollment.Worker.Binding.InstallationID || c.Owners == nil || c.Fences == nil || c.Origins.Operations == nil || c.Origins.Now == nil || c.Registrar == nil || c.PreparationKeys == nil || c.WindowKeys == nil || c.Authority == nil || c.Now == nil || c.NewID == nil {
		return nil, artifact.ErrInvalid
	}
	return &NativeAttachment{c}, nil
}

type attachedExchange struct {
	NativeExchange
	pending  NativePendingExchange
	release  *nativeOperationRelease
	once     sync.Once
	closeErr error
	renew    func(context.Context, NativePreparationCheck, artifact.DownloadDeliveryLease) error
}

// A positive completion and cancellation cleanup share one original close
// attempt. An unknown result is retained, never retried as a successful handoff.
type nativeOperationRelease struct {
	owners    NativeOperations
	operation value.NativeOperation
	once      sync.Once
	err       error
	positive  bool
}

func (r *nativeOperationRelease) complete(ctx context.Context, lease value.NativeLease) error {
	if ctx == nil || ctx.Err() != nil || !lease.Operation.Equal(r.operation) || !lease.Valid(time.Now()) {
		return artifact.ErrDownloadUnavailable
	}
	r.once.Do(func() { r.err = r.owners.CompleteNativeOperation(ctx, lease); r.positive = r.err == nil })
	if !r.positive || ctx.Err() != nil || !lease.Valid(time.Now()) {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (r *nativeOperationRelease) cleanup(ctx context.Context) error {
	r.once.Do(func() { r.err = r.owners.ReleaseNativeOperation(ctx, r.operation) })
	return r.err
}

func (e *attachedExchange) Close() error {
	if e == nil {
		return nil
	}
	e.once.Do(func() {
		e.pending.Close()
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		e.closeErr = e.release.cleanup(ctx)
	})
	return e.closeErr
}
func (s *NativeAttachment) open(ctx context.Context, r ContextDownloadRequest, kind value.NativeOperationKind, parent string, generation int64, delivery artifact.DownloadDeliveryLease, check NativePreparationCheck) (*attachedExchange, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || check == nil || !value.UUID(parent) || generation < 1 || r.SessionID != s.config.Enrollment.Worker.Intent.SessionID || r.Scope != s.config.Enrollment.Worker.Intent.Authority.Scope {
		return nil, artifact.ErrInvalid
	}
	c := s.config
	source := NativeContextSource{r.Expectation, r.Copies}
	if !source.Valid(r.Scope.Version) {
		return nil, artifact.ErrInvalid
	}
	initial, e := check(ctx)
	if e != nil || !initial.Valid(c.Now()) || !initial.Environment.CurrentValid(c.Now()) || initial.Environment.Path.AcquisitionClusterID != c.Enrollment.Worker.Intent.Profile.ClusterID || initial.Environment.Path.WorkerConfiguration != c.Enrollment.Worker.Intent.Profile.Configuration || initial.Scope != r.Scope {
		return nil, collapsed("attachment-initial", artifact.ErrDownloadUnavailable, e)
	}
	end := identity.Earlier(initial.ValidUntil, c.Enrollment.Worker.Intent.RunUntil).UTC().Truncate(time.Microsecond)
	if kind == value.NativeResponse {
		end = identity.Earlier(c.Now().Add(value.NativeConversationWindow(kind)), identity.Earlier(initial.AccessUntil, c.Enrollment.Worker.Intent.RunUntil)).UTC().Truncate(time.Microsecond)
	}
	if d, ok := ctx.Deadline(); ok {
		end = identity.Earlier(end, d)
	}
	// SQL normalizes operation times to microseconds. Clamp every original
	// bound first, then normalize by shortening so the exact returned identity
	// survives a nanosecond-precision caller/window deadline.
	end = end.UTC().Truncate(time.Microsecond)
	call, stop := context.WithDeadline(ctx, end)
	defer stop()
	fence, e := c.Fences.NextNativeFence(call, c.Enrollment.Worker.Intent.ID)
	if e != nil {
		return nil, stepped("attachment-fence", e)
	}
	operation := value.NativeOperation{Path: initial.Environment.Path, Processing: initial.Environment.Processing, Reference: value.NativeReference{InstallationID: c.Enrollment.Worker.Binding.InstallationID, SessionID: r.SessionID, WorkerID: c.Enrollment.Worker.Intent.ID, OperationID: c.NewID(), Fence: fence}, Kind: kind, HubPodUID: c.HubPodUID, HubProcessEpoch: c.HubProcessEpoch, WorkerPodUID: c.Enrollment.Worker.Binding.PodUID, WorkerPublicKey: c.Enrollment.PublicKeyDigest, SourceVersion: r.Scope.Version, ParentID: parent, Generation: generation, StartedAt: c.Now().UTC().Truncate(time.Microsecond), Until: end}
	if !operation.CurrentValid(c.Now()) {
		return nil, stepped("attachment-operation", artifact.ErrDownloadExpired)
	}
	var currentMu sync.Mutex
	var currentOrigin NativeOrigin
	current := func(bound context.Context, origin NativeOrigin) (value.NativeLease, error) {
		currentMu.Lock()
		defer currentMu.Unlock()
		if bound.Err() != nil || ctx.Err() != nil {
			return value.NativeLease{}, artifact.ErrDownloadExpired
		}
		currentOrigin = origin
		a, e := check(bound)
		if e != nil || !a.Valid(c.Now()) || !a.Environment.CurrentValid(c.Now()) || a.Environment.Path != operation.Path || a.Environment.Processing.Epoch != operation.Processing.Epoch || a.Environment.Processing.Sequence != operation.Processing.Sequence || a.Environment.Processing.StateDigest != operation.Processing.StateDigest || a.Scope != r.Scope {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		l, e := c.Origins.Recheck(bound, origin)
		if e != nil || !l.Operation.Equal(operation) || origin.Proof.Binding != c.Enrollment.Worker.Binding.Acquisition() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		l.Until = identity.Earlier(l.Until, identity.Earlier(a.ValidUntil, end))
		if !l.Valid(c.Now()) || bound.Err() != nil || ctx.Err() != nil {
			return value.NativeLease{}, artifact.ErrDownloadExpired
		}
		return l, nil
	}
	before := func(bound context.Context, origin NativeOrigin) error {
		l, e := current(bound, origin)
		if e != nil {
			return e
		}
		a, e := check(bound)
		if e != nil {
			return e
		}
		effect, cancel := context.WithDeadline(bound, l.Until)
		defer cancel()
		proof, ok := origin.Proof.DownloadProof()
		if !ok {
			return artifact.ErrInvalid
		}
		switch kind {
		case value.NativePrepare:
			e = c.PreparationKeys.BindAttestedDownloadKeys(effect, r.SessionID, a, parent, generation, c.KeyScope, proof.Peer, proof)
		case value.NativeResponse:
			e = c.WindowKeys.BindNativeDownloadKeys(effect, operation.Reference, delivery, c.KeyScope, proof.Peer, proof)
		case value.NativeObserve:
		default:
			return artifact.ErrInvalid
		}
		if e != nil {
			return e
		}
		_, e = current(effect, origin)
		return e
	}
	// Register first: a persisted locator without a live original request must
	// never become runnable. An unknown claim closes local admission and stays spent.
	release := &nativeOperationRelease{owners: c.Owners, operation: operation}
	pending, e := c.Registrar.RegisterNativeExchange(ctx, NativeExchangeRegistration{Operation: operation, Source: cloneNativeSource(source), Delivery: delivery, Complete: release.complete}, before, current)
	if e != nil {
		return nil, stepped("attachment-register", e)
	}
	claimed, e := c.Owners.ClaimNativeOperation(call, c.Enrollment, initial, operation)
	if e != nil || !claimed.Equal(operation) || call.Err() != nil {
		pending.Close()
		if e == nil {
			e = artifact.ErrDownloadUnavailable
		}
		return nil, stepped("attachment-claim", e)
	}
	exchange, e := pending.Wait(call)
	if e != nil {
		pending.Close()
		cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		_ = release.cleanup(cleanup)
		done()
		return nil, stepped("attachment-wait", e)
	}
	attached := &attachedExchange{NativeExchange: exchange, pending: pending, release: release}
	if kind == value.NativeResponse {
		attached.renew = func(bound context.Context, next NativePreparationCheck, l artifact.DownloadDeliveryLease) error {
			currentMu.Lock()
			defer currentMu.Unlock()
			if next == nil || !SameNativeWindow(delivery, l) || l.Sequence <= delivery.Sequence || !l.Valid(c.Now()) || !c.Now().Before(end) || ctx.Err() != nil {
				return artifact.ErrDownloadUnavailable
			}
			a, err := next(bound)
			if err != nil {
				return err
			}
			_, err = c.Origins.proofBound(bound, currentOrigin)
			if err != nil {
				return err
			}
			renewer, ok := c.Owners.(NativeOperationRenewer)
			if !ok {
				return artifact.ErrDownloadUnavailable
			}
			renewed, err := renewer.RenewNativeOperation(bound, operation.Reference, a, currentOrigin.Proof.Peer)
			if err != nil || !renewed.Operation.Equal(operation) || renewed.Sequence != l.Sequence || renewed.Certificate != currentOrigin.Lease.Certificate || !renewed.Valid(c.Now()) || bound.Err() != nil {
				return artifact.ErrDownloadUnavailable
			}
			c.Origins.Recent.put(nativeObservationKey{operation.Reference, currentOrigin.Proof.Peer}, renewed, c.Now())
			check, delivery = next, l
			return nil
		}
	}
	return attached, nil
}
func (s *NativeAttachment) PrepareNativeMetadata(ctx context.Context, r ContextDownloadRequest, i audit.DownloadIntent, a artifact.DownloadAuthority, check NativePreparationCheck) (artifact.NativeDownloadMetadata, NativePreparationCommit, error) {
	if !i.Valid() || i.SessionID != r.SessionID || i.Batch.Purpose != artifact.DownloadMetadata || i.Batch.Authority.Scope != r.Scope || a.Scope != r.Scope {
		return artifact.NativeDownloadMetadata{}, nil, artifact.ErrInvalid
	}
	exchange, e := s.open(ctx, r, value.NativePrepare, i.Batch.ID, i.Batch.Generation, artifact.DownloadDeliveryLease{}, check)
	if e != nil {
		return artifact.NativeDownloadMetadata{}, nil, e
	}
	metadata, e := exchange.Prepared(ctx)
	if e != nil {
		exchange.Close()
		return artifact.NativeDownloadMetadata{}, nil, e
	}
	return metadata, exchange, nil
}
func (s *NativeAttachment) current(ctx context.Context, current identities.CurrentIdentity, r ContextDownloadRequest) (NativePreparationCheck, error) {
	return s.currentAuthority(ctx, current, r, nil)
}

// A private response handoff consumes the coordinator's already checked lease.
// Direct callers still construct their complete independent authority.
func (s *NativeAttachment) currentAuthority(ctx context.Context, current identities.CurrentIdentity, r ContextDownloadRequest, observed *artifact.DownloadAuthority) (NativePreparationCheck, error) {
	if s == nil {
		return nil, artifact.ErrInvalid
	}
	var check *workerCurrentCheck
	var e error
	if observed == nil {
		check, e = newWorkerCurrentCheck(ctx, current, s.config.Authority, r.Scope, s.config.Now)
	} else {
		check, _, e = newWorkerResponseObservation(ctx, current, *observed, r.Scope, s.config.Now)
	}
	if e != nil {
		return nil, e
	}
	return func(call context.Context) (artifact.DownloadAuthority, error) {
		a, e := check.Check(call)
		if e != nil {
			return a, e
		}
		if a.Environment.StoreID != r.Expectation.Registration.StoreID || a.Environment.Location != r.Expectation.Registration.Location || a.AccessUntil.After(r.Expectation.Registration.ExpiresAt) || a.DeleteBy.IsZero() || a.DeleteBy.After(r.Expectation.Registration.DeleteBy) {
			return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
		}
		return a, nil
	}, nil
}
