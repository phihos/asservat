package bootstrap

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type installedAuditCredentialReader interface {
	ReadAuditCredentials(context.Context) (contracts.OwnerStorageCredential, time.Time, error)
}

// Only the installed provider layout uses this operation-owned adapter. It
// preserves the existing C08 create/find and positive closure contracts.
type installedOperationAudit struct {
	input     contracts.OwnerDeployment
	providers installedAuditCredentialReader
	http      *http.Client
	seal      evidence.KeySealer
	open      evidence.KeyOpener
	storeID   string
	slots     chan struct{}
}

var _ auditapp.OperationObjects = (*installedOperationAudit)(nil)
var _ auditapp.ClosedOperationObjects = (*installedOperationAudit)(nil)

func (s *installedOperationAudit) storage(ctx context.Context, until time.Time) (context.Context, *objectstore.Store, func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil || s.providers == nil || s.http == nil || s.seal == nil || s.open == nil || s.slots == nil || !time.Now().Before(until) {
		return nil, nil, nil, mounts.ErrUnavailable
	}
	call, end := context.WithDeadline(ctx, until)
	call, finite := context.WithTimeout(call, 5*time.Second)
	// Private transports must not multiply the accepted shared connection bound.
	// One slot covers proof, every signed request, joined body close and teardown.
	select {
	case s.slots <- struct{}{}:
	case <-call.Done():
		finite()
		end()
		return nil, nil, nil, mounts.ErrUnavailable
	}
	release := func() { <-s.slots }
	if !auditOperationCurrent(call) {
		finite()
		end()
		release()
		return nil, nil, nil, mounts.ErrUnavailable
	}
	material, observedUntil, err := s.providers.ReadAuditCredentials(call)
	if err != nil || !auditOperationCurrent(call) || !time.Now().Before(observedUntil) {
		finite()
		end()
		release()
		if err != nil {
			return nil, nil, nil, auditCredentialFailure(err)
		}
		return nil, nil, nil, &fixedStepError{"credentials-expired", mounts.ErrUnavailable}
	}
	// One observation, owned only by this finite encrypted audit operation.
	// Its original bound covers seal, signed PUT, exact GET, body close and
	// verification. Expiring AWS credentials alone cannot cancel signed I/O.
	call, narrow := context.WithDeadline(call, observedUntil)
	cleanup := func() { narrow(); finite(); end() }
	store, err := objectstore.NewVersionedAudit(s.input.AuditStore.Endpoint, s.input.AuditStore.Region, s.input.AuditStore.Bucket, credentials.NewStaticCredentialsProvider(material.AccessKeyID, material.SecretAccessKey, material.SessionToken), s.http)
	if err != nil {
		cleanup()
		release()
		return nil, nil, nil, err
	}
	if !auditOperationCurrent(call) {
		cleanup()
		store.Close()
		release()
		return nil, nil, nil, mounts.ErrUnavailable
	}
	return call, store, func() { cleanup(); store.Close(); release() }, nil
}

func (s *installedOperationAudit) operation(ctx context.Context, until time.Time) (context.Context, *objectstore.OperationAuditObjects, *objectstore.ClosedOperationAuditObjects, func(), error) {
	call, store, done, err := s.storage(ctx, until)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	closed, err := objectstore.NewClosedOperationAuditObjects(store, s.storeID, s.seal, s.open)
	if err != nil {
		done()
		return nil, nil, nil, nil, err
	}
	return call, &objectstore.OperationAuditObjects{Store: store, Seal: s.seal, Open: s.open}, closed, done, nil
}

func auditOperationCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	until, ok := ctx.Deadline()
	return ok && time.Now().Before(until)
}

// The callback is private bootstrap composition, never a supplied authority or
// a detached operation. Every synchronous typed writer closes its body before
// returning; the owner then checks the original bound and closes the transport.
func withInstalledAudit[T any](ctx context.Context, s *installedOperationAudit, until time.Time, run func(context.Context, *objectstore.Store) (T, error)) (T, error) {
	var zero T
	call, store, done, err := s.storage(ctx, until)
	if err != nil {
		return zero, err
	}
	defer done()
	out, err := run(call, store)
	if err != nil {
		return zero, err
	}
	if !auditOperationCurrent(call) {
		return zero, mounts.ErrUnavailable
	}
	return out, nil
}

func (s *installedOperationAudit) intent(ctx context.Context, in audit.OperationIntent, create bool) (audit.Receipt, error) {
	if !in.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	call, legacy, _, done, err := s.operation(ctx, in.WriteUntil)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer done()
	var r audit.Receipt
	if create {
		r, err = legacy.CreateOperationIntent(call, in)
	} else {
		r, err = legacy.FindOperationIntent(call, in)
	}
	if err != nil {
		return audit.Receipt{}, err
	}
	if !auditOperationCurrent(call) {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return r, nil
}
func (s *installedOperationAudit) outcome(ctx context.Context, in audit.OperationOutcome, create bool) (audit.Receipt, error) {
	if !in.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	call, legacy, _, done, err := s.operation(ctx, in.Intent.WriteUntil)
	if err != nil {
		return audit.Receipt{}, err
	}
	defer done()
	var r audit.Receipt
	if create {
		r, err = legacy.CreateOperationOutcome(call, in)
	} else {
		r, err = legacy.FindOperationOutcome(call, in)
	}
	if err != nil {
		return audit.Receipt{}, err
	}
	if !auditOperationCurrent(call) {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return r, nil
}
func (s *installedOperationAudit) CreateOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	return s.intent(ctx, in, true)
}
func (s *installedOperationAudit) FindOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	return s.intent(ctx, in, false)
}
func (s *installedOperationAudit) CreateOperationOutcome(ctx context.Context, in audit.OperationOutcome) (audit.Receipt, error) {
	return s.outcome(ctx, in, true)
}
func (s *installedOperationAudit) FindOperationOutcome(ctx context.Context, in audit.OperationOutcome) (audit.Receipt, error) {
	return s.outcome(ctx, in, false)
}
func (s *installedOperationAudit) CreateClosedOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.OperationWriteCompletion, error) {
	if !in.Valid() {
		return audit.OperationWriteCompletion{}, mounts.ErrUnavailable
	}
	call, _, closed, done, err := s.operation(ctx, in.WriteUntil)
	if err != nil {
		return audit.OperationWriteCompletion{}, err
	}
	defer done()
	r, err := closed.CreateClosedOperationIntent(call, in)
	if err != nil {
		return audit.OperationWriteCompletion{}, err
	}
	if !auditOperationCurrent(call) {
		return audit.OperationWriteCompletion{}, mounts.ErrUnavailable
	}
	return r, nil
}
func (s *installedOperationAudit) CreateClosedOperationOutcome(ctx context.Context, in audit.OperationOutcome) (audit.OperationWriteCompletion, error) {
	if !in.Valid() {
		return audit.OperationWriteCompletion{}, mounts.ErrUnavailable
	}
	call, _, closed, done, err := s.operation(ctx, in.Intent.WriteUntil)
	if err != nil {
		return audit.OperationWriteCompletion{}, err
	}
	defer done()
	r, err := closed.CreateClosedOperationOutcome(call, in)
	if err != nil {
		return audit.OperationWriteCompletion{}, err
	}
	if !auditOperationCurrent(call) {
		return audit.OperationWriteCompletion{}, mounts.ErrUnavailable
	}
	return r, nil
}

// Legacy installations retain their existing material contract. The installed
// provider layout owns a separate credential observation per create or lookup;
// no shared SDK cache or previous invocation can extend it.
func (a publicAuditStore) operationObjects(storeID string) (auditapp.OperationObjects, auditapp.ClosedOperationObjects, error) {
	if a.operation != nil {
		s := *a.operation
		s.storeID = storeID
		return &s, &s, nil
	}
	closed, err := objectstore.NewClosedOperationAuditObjects(a.store, storeID, a.seal, a.open)
	if err != nil {
		return nil, nil, err
	}
	return &objectstore.OperationAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}, closed, nil
}
