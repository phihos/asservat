package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// ContextNativeReader is the bounded initial acquisition-role facet. A current
// disclosed-artifact lease, accepted catalog provenance and durable audit must
// precede calls. Hub/control roles must not receive the reader's unwrap keys.
// Ownership of returned plaintext passes to the caller, which must clear it
// after bounded delivery; it is never a SQL, outbox or MCP result payload.
type ContextNativeReader interface {
	ReadContext(context.Context, artifact.ContextExpectation, artifact.Copies, time.Time) ([]byte, error)
}

// A local-provider reader binds its remote key facet only after the batch is
// prepaid, audited and currently permitted. It cannot reuse a previous batch.
type ContextBatchNativeReader interface {
	ReadContextBatch(context.Context, artifact.ContextExpectation, artifact.Copies, audit.DownloadIntent, artifact.DownloadAuthority) ([]byte, error)
}

// The trusted download coordinator supplies the verified acquisition peer.
// In production this port is mediated by authenticated control, never exposed
// as an arbitrary public certificate or key-grant creation endpoint.
type DownloadKeyGrants interface {
	BindDownloadKeys(context.Context, string, artifact.DownloadAuthority, string, int64, authorization.KeyScope, authorization.KeyPeer) error
}
