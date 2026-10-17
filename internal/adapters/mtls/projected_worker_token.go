package mtls

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"context"
	"os"
	"path/filepath"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

const DownloadWorkerTokenPath = contracts.WorkerTokenPath

type projectedWorkerToken struct{ path string }

// The restricted Job template owns this projected mount. No public request or
// ambient environment can select a filesystem credential. Kubernetes rotates
// projection symlinks, so each call opens the fixed path anew and reads one FD.
func NewProjectedWorkerToken() evidence.DownloadPeerToken {
	return projectedWorkerToken{path: DownloadWorkerTokenPath}
}

func (p projectedWorkerToken) ReadDownloadPeerToken(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	root, err := os.OpenRoot(filepath.Dir(p.path))
	if err != nil {
		return nil, artifact.ErrDownloadUnavailable
	}
	defer root.Close()
	b, err := mounts.Read(ctx, root, filepath.Base(p.path), contracts.WorkerEnrollmentMaxToken)
	if err != nil || ctx.Err() != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, artifact.ErrDownloadUnavailable
	}
	return b, nil
}
