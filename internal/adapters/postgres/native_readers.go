package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NativeReaders resolves only the exact current admitted worker profile under
// one installed permission root. The read/lock SQL credential cannot claim or
// release native operations, bind keys, dispatch workers or change authority.
// Profiles never come from a Hello, and no profile/effect adapter is cached.
type NativeReaders struct {
	downloads    *Downloads
	installation string
}

var _ evidence.NativeOperationReader = (*NativeReaders)(nil)
var _ evidence.NativeLocator = (*NativeReaders)(nil)
var _ evidence.WorkerEnrollmentBindings = (*NativeReaders)(nil)
var _ evidence.DownloadWorkerBindings = (*NativeReaders)(nil)

func NewNativeReaders(ctx context.Context, pool *pgxpool.Pool, root, installation string, guards DownloadTransactionGuards) (*NativeReaders, error) {
	if !value.UUID(installation) || guards.Recovery == nil || guards.Recovery.installation != installation {
		return nil, artifact.ErrInvalid
	}
	downloads, err := NewDownloads(ctx, pool, root, guards)
	if err != nil {
		return nil, err
	}
	return &NativeReaders{downloads, installation}, nil
}
func (s *NativeReaders) withWorker(ctx context.Context, session, worker string, read func(context.Context, *NativeOwners, value.DownloadWorkerIdentity) error) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !value.UUID(session) || worker != "" && !value.UUID(worker) || read == nil {
		return artifact.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	observation, err := readWorkerIdentity(call, s.downloads.ledger, s.downloads.root, s.installation, nil, session)
	if err != nil || !observation.Valid(time.Now()) || worker != "" && observation.Worker.Intent.ID != worker {
		return artifact.ErrDownloadUnavailable
	}
	current, finish := context.WithDeadline(call, observation.FreshUntil)
	defer finish()
	owners := &NativeOwners{&DownloadWorkers{s.downloads, observation.Worker.Intent.Profile}}
	err = read(current, owners, observation)
	if current.Err() != nil || !observation.Valid(time.Now()) {
		return artifact.ErrDownloadExpired
	}
	return err
}
func (s *NativeReaders) ReadDownloadWorkerEnrollment(ctx context.Context, session, worker string) (out value.DownloadWorkerIdentity, err error) {
	if !value.UUID(worker) {
		return out, artifact.ErrInvalid
	}
	err = s.withWorker(ctx, session, worker, func(_ context.Context, _ *NativeOwners, observed value.DownloadWorkerIdentity) error {
		out = observed
		return nil
	})
	if err != nil {
		return value.DownloadWorkerIdentity{}, err
	}
	return out, nil
}
func (s *NativeReaders) ReadDownloadWorkerIdentity(ctx context.Context, session string, peer value.KeyPeer) (out value.DownloadWorkerIdentity, err error) {
	err = s.withWorker(ctx, session, "", func(call context.Context, owners *NativeOwners, _ value.DownloadWorkerIdentity) error {
		var e error
		out, e = owners.workers.ReadDownloadWorkerIdentity(call, session, peer)
		return e
	})
	if err != nil {
		return value.DownloadWorkerIdentity{}, err
	}
	return out, nil
}
func (s *NativeReaders) ObserveNativeOperation(ctx context.Context, ref value.NativeReference, peer value.KeyPeer) (out value.NativeLease, err error) {
	if s == nil || ref.InstallationID != s.installation {
		return out, artifact.ErrDownloadUnavailable
	}
	err = s.withWorker(ctx, ref.SessionID, ref.WorkerID, func(call context.Context, owners *NativeOwners, _ value.DownloadWorkerIdentity) error {
		var e error
		out, e = owners.ObserveNativeOperation(call, ref, peer)
		return e
	})
	if err != nil {
		return value.NativeLease{}, err
	}
	return out, nil
}
func (s *NativeReaders) LocateNativeOperation(ctx context.Context, installation, session, worker string, peer value.KeyPeer) (out value.NativeLease, err error) {
	if s == nil || installation != s.installation {
		return out, artifact.ErrDownloadUnavailable
	}
	err = s.withWorker(ctx, session, worker, func(call context.Context, owners *NativeOwners, _ value.DownloadWorkerIdentity) error {
		var e error
		out, e = owners.LocateNativeOperation(call, installation, session, worker, peer)
		return e
	})
	if err != nil {
		return value.NativeLease{}, err
	}
	return out, nil
}
func (s *NativeReaders) ReadNativeWorkerCertificate(ctx context.Context, session, worker string, leaf []byte) (out value.WorkerCertificate, err error) {
	if !value.UUID(worker) || len(leaf) < 1 || len(leaf) > 16<<10 {
		return out, artifact.ErrInvalid
	}
	err = s.withWorker(ctx, session, worker, func(call context.Context, owners *NativeOwners, _ value.DownloadWorkerIdentity) error {
		var e error
		out, e = owners.ReadNativeWorkerCertificate(call, session, worker, leaf)
		return e
	})
	if err != nil {
		return value.WorkerCertificate{}, err
	}
	return out, nil
}
