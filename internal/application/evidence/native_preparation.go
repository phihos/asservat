package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"encoding/hex"
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

func validRegionalMetadata(r ContextDownloadRequest, m artifact.NativeDownloadMetadata) bool {
	return m.Filename == "artifact-"+r.Scope.ArtifactID+".json" && m.Format == artifact.ContextFormat && m.ETag == `"v1-`+hex.EncodeToString(r.Scope.Version[:])+`"` && m.Coverage == "Selected pod-status fields only; no logs, messages or workload configuration." && m.Size >= 1 && m.Size <= artifact.MaxContextBytes && m.SHA256 != (artifact.Digest{}) && m.ReadUntil.Equal(r.Expectation.Registration.ExpiresAt) && m.DeleteBy.Equal(r.Expectation.Registration.DeleteBy)
}
