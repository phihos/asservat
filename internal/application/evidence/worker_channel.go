package evidence

import (
	"bytes"
	"context"
	"sync"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// WorkerEnrollmentExchange is the private bootstrap ingress. Implementations
// must resolve current human authority from trusted active control, never from
// the worker token, CSR, a supplied principal or an offline identity snapshot.
type WorkerEnrollmentExchange interface {
	BeginWorkerEnrollment(context.Context, string, string, string, []byte, []byte) (WorkerEnrollmentDelivery, error)
}

// Delivery retains the original request owner's cancellation/deadline through
// the response write. Close is mandatory even when no response bytes are sent.
// This is a private in-process lifetime, never a serialized bearer capability.
type WorkerEnrollmentDelivery interface {
	Certificate() value.WorkerCertificate
	Context() context.Context
	Close()
}

type workerEnrollmentDelivery struct {
	ctx         context.Context
	certificate value.WorkerCertificate
	release     func()
	once        sync.Once
}

func (d *workerEnrollmentDelivery) Certificate() value.WorkerCertificate { return d.certificate }
func (d *workerEnrollmentDelivery) Context() context.Context             { return d.ctx }
func (d *workerEnrollmentDelivery) Close()                               { d.once.Do(d.release) }

func (s *WorkerEnrollmentOperation) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (WorkerEnrollmentDelivery, error) {
	if s == nil || s.parent == nil || ctx == nil {
		return nil, artifact.ErrInvalid
	}
	owner, cancel := context.WithDeadline(ctx, s.bound())
	stop := context.AfterFunc(s.parent, cancel)
	release := func() { stop(); cancel() }
	c, err := s.EnrollWorker(owner, installation, session, worker, token, csr)
	if err != nil || owner.Err() != nil || s.parent.Err() != nil {
		release()
		if err != nil {
			return nil, err
		}
		return nil, artifact.ErrDownloadExpired
	}
	if s.pinned != nil {
		shorter, stopShort := context.WithDeadline(owner, s.bound())
		previous := release
		release = func() { stopShort(); previous() }
		owner = shorter
	}
	return &workerEnrollmentDelivery{ctx: owner, certificate: c, release: release}, nil
}

// WorkerProofFactory creates request-owned proof readers so simultaneous
// workers cannot overwrite each other's token. The reader still performs real
// TokenReview and exact live worker/configuration checks.
type WorkerProofFactory func(DownloadPeerToken) (WorkerEnrollmentProofReader, error)

type WorkerEnrollmentOperation struct {
	parent     context.Context
	until      time.Time
	service    WorkerEnrollmentCoordinator
	proofs     WorkerProofFactory
	credential string
	target     value.WorkerCredentialTarget
	scope      artifact.DownloadScope
	pinned     *workerCurrentCheck
}

// This operation belongs to a live authenticated control request (at most
// thirty seconds). It is not a durable token store or a worker routing registry.
// An owner relay must reconnect it to current browser/MCP authority on retry.
func NewWorkerEnrollmentOperation(parent context.Context, service WorkerEnrollmentCoordinator, proofs WorkerProofFactory, credential string, target value.WorkerCredentialTarget, scope artifact.DownloadScope) (*WorkerEnrollmentOperation, error) {
	if parent == nil || parent.Err() != nil || service.Now == nil || service.CSR == nil || service.Ledger == nil || service.Activation == nil || service.Audit == nil || service.Acknowledgements == nil || service.Issuer == nil || service.Authority == nil || proofs == nil || len(credential) == 0 || len(credential) > 32<<10 || !target.Valid() || !scope.Valid() {
		return nil, artifact.ErrInvalid
	}
	until := service.Now().Add(30 * time.Second)
	if d, ok := parent.Deadline(); ok && d.Before(until) {
		until = d
	}
	if target.RunUntil.Before(until) {
		until = target.RunUntil
	}
	if service.Now().Before(target.CreatedAt) || !service.Now().Before(until) {
		return nil, artifact.ErrInvalid
	}
	return &WorkerEnrollmentOperation{parent: parent, until: until, service: service, proofs: proofs, credential: credential, target: target, scope: scope}, nil
}

// NewCurrentWorkerEnrollmentOperation retains the actual request-owned identity
// in the hub. No personal credential or CurrentIdentity crosses the private wire.
func NewCurrentWorkerEnrollmentOperation(parent context.Context, service WorkerEnrollmentCoordinator, proofs WorkerProofFactory, source identities.CurrentIdentity, target value.WorkerCredentialTarget, scope artifact.DownloadScope) (*WorkerEnrollmentOperation, error) {
	if parent == nil || parent.Err() != nil || service.Now == nil || service.CSR == nil || service.Ledger == nil || service.Activation == nil || service.Audit == nil || service.Acknowledgements == nil || service.Issuer == nil || service.CurrentAuthority == nil || proofs == nil || !target.Valid() || !scope.Valid() {
		return nil, artifact.ErrInvalid
	}
	check, err := newWorkerCurrentCheck(parent, source, service.CurrentAuthority, scope, service.Now)
	if err != nil {
		return nil, err
	}
	until := check.Deadline()
	if target.RunUntil.Before(until) {
		until = target.RunUntil
	}
	if service.Now().Before(target.CreatedAt) || !service.Now().Before(until) {
		return nil, artifact.ErrDownloadExpired
	}
	return &WorkerEnrollmentOperation{parent: parent, until: until, service: service, proofs: proofs, target: target, scope: scope, pinned: check}, nil
}
func (s *WorkerEnrollmentOperation) bound() time.Time {
	until := s.until
	if s.pinned != nil && s.pinned.Deadline().Before(until) {
		until = s.pinned.Deadline()
	}
	return until
}
func (s *WorkerEnrollmentOperation) hasAuthority() bool {
	return s != nil && (s.pinned != nil || s.service.Authority != nil)
}
func (s *WorkerEnrollmentOperation) current(ctx context.Context) (artifact.DownloadAuthority, error) {
	if s == nil || ctx == nil || s.parent == nil || s.parent.Err() != nil || ctx.Err() != nil || s.service.Now == nil || !s.service.Now().Before(s.bound()) {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadExpired
	}
	if s.pinned != nil {
		return s.pinned.Check(ctx)
	}
	if s.service.Authority == nil {
		return artifact.DownloadAuthority{}, artifact.ErrInvalid
	}
	return s.service.Authority.CheckDownload(ctx, s.credential, s.scope)
}

type enrollmentToken []byte

func (t enrollmentToken) ReadDownloadPeerToken(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(t) == 0 {
		return nil, artifact.ErrInvalid
	}
	return bytes.Clone(t), nil
}

func (s *WorkerEnrollmentOperation) EnrollWorker(ctx context.Context, installation, session, worker string, token, csr []byte) (value.WorkerCertificate, error) {
	var zero value.WorkerCertificate
	if s == nil || s.parent == nil || s.service.Now == nil || s.proofs == nil || ctx == nil || s.parent.Err() != nil || ctx.Err() != nil || !s.service.Now().Before(s.bound()) || installation != s.target.InstallationID || session != s.target.SessionID || worker != s.target.WorkerID || len(token) < 1 || len(token) > 16<<10 || len(csr) < 1 || len(csr) > 8192 {
		return zero, artifact.ErrDownloadUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, s.bound())
	defer cancel()
	stop := context.AfterFunc(s.parent, cancel)
	defer stop()
	owned := enrollmentToken(bytes.Clone(token))
	defer clear(owned)
	proofs, err := s.proofs(owned)
	if err != nil || proofs == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	service := s.service
	service.Proofs = targetWorkerProof{proofs, s.target}
	cert, err := service.enrollChecked(ctx, s.target.SessionID, s.target.WorkerID, s.scope, csr, s.current, s.bound)
	if err != nil || ctx.Err() != nil || s.parent.Err() != nil || !s.service.Now().Before(s.bound()) {
		return zero, artifact.ErrDownloadUnavailable
	}
	return cert, nil
}

// Public worker timing/identity pins must match the current trusted registry.
type targetWorkerProof struct {
	reader WorkerEnrollmentProofReader
	target value.WorkerCredentialTarget
}

func (s targetWorkerProof) ReadWorkerEnrollmentProof(ctx context.Context, session, worker string, key artifact.Digest) (value.WorkerEnrollmentProof, error) {
	p, err := s.reader.ReadWorkerEnrollmentProof(ctx, session, worker, key)
	w := p.Worker
	got := value.WorkerCredentialTarget{InstallationID: w.Binding.InstallationID, SessionID: w.Intent.SessionID, WorkerID: w.Intent.ID, PodUID: w.Binding.PodUID, CreatedAt: w.Intent.CreatedAt, RunUntil: w.Intent.RunUntil}
	if err != nil || got.InstallationID != s.target.InstallationID || got.SessionID != s.target.SessionID || got.WorkerID != s.target.WorkerID || got.PodUID != s.target.PodUID || !got.CreatedAt.Equal(s.target.CreatedAt) || !got.RunUntil.Equal(s.target.RunUntil) {
		return value.WorkerEnrollmentProof{}, artifact.ErrDownloadUnavailable
	}
	return p, nil
}
