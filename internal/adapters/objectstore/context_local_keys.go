package objectstore

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// LocalKeyContextReader is a regional acquisition adapter. The trusted
// coordinator's grant port is separately credentialed; production mediation
// must authenticate the exact peer from this process's current TLS identity.
// No root key or general unwrap provider is present in this reader.
type LocalKeyContextReader struct {
	store    *CustodyStore
	grants   evidence.DownloadKeyGrants
	scope    authorization.KeyScope
	peer     authorization.KeyPeer
	endpoint string
	client   *http.Client
}

var _ evidence.ContextBatchNativeReader = (*LocalKeyContextReader)(nil)

func NewLocalKeyContextReader(store *CustodyStore, grants evidence.DownloadKeyGrants, scope authorization.KeyScope, peer authorization.KeyPeer, endpoint string, client *http.Client) (*LocalKeyContextReader, error) {
	if store == nil || grants == nil || !scope.Valid() || scope.Purpose != "artifact" || peer.Role != "acquisition" || !peer.Valid(time.Now()) || !peer.CanRequest(scope, "unwrap") {
		return nil, artifact.ErrInvalid
	}
	// Constructor validation owns no key or authority; use a disposable client
	// only to validate pinned HTTPS/TLS configuration, then release its pool.
	check, err := kms.NewRemoteOpener(endpoint, scope, peer.PeerID, client)
	if err != nil {
		return nil, err
	}
	check.Close()
	return &LocalKeyContextReader{store, grants, scope, peer, endpoint, client}, nil
}

func (r *LocalKeyContextReader) ReadContextBatch(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, i audit.DownloadIntent, a artifact.DownloadAuthority) ([]byte, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !i.Valid() || e.Validate() != nil || e.DataClass != "metadata" || !a.Valid(time.Now()) || i.Batch.Authority.Scope != a.Scope || a.Scope.ArtifactID != e.Registration.Location.ArtifactID || a.Scope.CaptureID != e.CaptureUID || a.Scope.Version != evidence.ContextCopiesDigest(c) {
		return nil, artifact.ErrInvalid
	}
	deadline := minDeadline(i.Batch.LeaseUntil, a.ValidUntil)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := r.grants.BindDownloadKeys(ctx, i.SessionID, a, i.Batch.ID, i.Batch.Generation, r.scope, r.peer); err != nil {
		return nil, err
	}
	opener, err := kms.NewRemoteOpener(r.endpoint, r.scope, i.Batch.ID, r.client)
	if err != nil {
		return nil, err
	}
	defer opener.Close()
	reader, err := NewContextNativeReader(r.store, opener)
	if err != nil {
		return nil, err
	}
	return reader.ReadContext(ctx, e, c, deadline)
}
