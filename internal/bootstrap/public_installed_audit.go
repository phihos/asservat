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
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type installedAuditCredentialReader interface {
	ReadAuditCredentials(context.Context) (contracts.OwnerStorageCredential, time.Time, error)
}

// installedAudit writes the provider-layout audit objects (download, worker
// and policy acceptance records) with a fresh credential observation per write.
type installedAudit struct {
	input     contracts.OwnerDeployment
	providers installedAuditCredentialReader
	http      *http.Client
	seal      evidence.KeySealer
	open      evidence.KeyOpener
	storeID   string
	slots     chan struct{}
}

func (s *installedAudit) storage(ctx context.Context, until time.Time) (context.Context, *objectstore.Store, func(), error) {
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
	started := time.Now()
	material, observedUntil, err := s.providers.ReadAuditCredentials(call)
	auditapp.MarkStep(ctx, "credentials", started)
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
func withInstalledAudit[T any](ctx context.Context, s *installedAudit, until time.Time, run func(context.Context, *objectstore.Store) (T, error)) (T, error) {
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
