package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

// NativePreparationCheck is a live original hub-request callback. It is never
// encoded, stored in a worker, or converted into a delegated bearer credential.
type NativePreparationCheck func(context.Context) (artifact.DownloadAuthority, error)
type NativePreparationCommit interface {
	Commit(context.Context) error
	Close() error
}

// RegionalPreparation supplies verified metadata only. Positive SQL/outcome
// audit acknowledgement must precede Commit; uncertainty cannot start a new
// read, batch or key operation. Close joins the original private conversation.
type RegionalPreparation interface {
	PrepareNativeMetadata(context.Context, ContextDownloadRequest, audit.DownloadIntent, artifact.DownloadAuthority, NativePreparationCheck) (artifact.NativeDownloadMetadata, NativePreparationCommit, error)
}

// validRegionalMetadata compares worker-reported metadata with the facts the
// hub derives from its own expectation: the type's filename, format, coverage
// and size bound, the requested version's ETag and the registered dates.
func validRegionalMetadata(r ContextDownloadRequest, m artifact.NativeDownloadMetadata) bool {
	return m.ETag == NativeETag(r.Scope.Version) && ValidNativeSourceMetadata(NativeContextSource{r.Expectation, r.Copies}, m)
}
