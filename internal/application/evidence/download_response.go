package evidence

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"time"
)

// Response operations are private typed ports. Neither public request JSON nor
// worker certificates supply an authority, owner, plan or control allocation.
// Unknown admission replies are not reusable writer permits.
type DownloadResponses interface {
	BeginDownloadResponse(context.Context, string, artifact.DownloadAuthority, artifact.DownloadResponse) (artifact.DownloadResponse, error)
	BeginDownloadWindow(context.Context, string, string, string, string, artifact.DownloadAuthority) (audit.DownloadWindowIntent, error)
	LeaseDownloadResponse(context.Context, string, string, string, string, artifact.DownloadAuthority) (artifact.DownloadDeliveryLease, error)
	FinishDownloadWindow(context.Context, audit.DownloadWindowIntent, artifact.DownloadWindowOutcome) (audit.DownloadWindowAuditOutcome, error)
	CloseDownloadResponse(context.Context, string, string, string) error
}
type DownloadWindowAcknowledgements interface {
	AcknowledgeDownloadWindowIntent(context.Context, audit.DownloadWindowIntent, audit.DownloadWindowWriteResult) error
	AcknowledgeDownloadWindowOutcome(context.Context, audit.DownloadWindowAuditOutcome, audit.DownloadWindowWriteResult) error
}

// NativeResponseSource is an independently authenticated regional source. Its
// adapter must bind the exact admitted worker/session/version/response generation
// and enforce current delivery leases; a caller-supplied value is not a permit.
// No implementation or public native endpoint is enabled by this interface.
// Metadata and plan are verified facts, never a second decrypt on status reads.
type NativeResponseSource interface {
	Describe(context.Context, artifact.DownloadSession, artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error)
	ReadChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error)
	Close()
}

// CurrentNativeResponseSource is mandatory for remote composition. The hub
// supplies its existing live IdentityBatch; an encoded delivery lease cannot
// recreate the human whose current checks must own the private conversation.
// Implementations must not retain the identity beyond this batch/operation.
type CurrentNativeResponseSource interface {
	NativeResponseSource
	NativeResponseDeliveryAcknowledger
	DescribeCurrent(context.Context, identities.CurrentIdentity, artifact.DownloadSession, artifact.DownloadAuthority) (artifact.NativeDownloadMetadata, int64, error)
	ReadChunkCurrent(context.Context, identities.CurrentIdentity, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error)
}

// NativeResponseDeliveryAcknowledger is mandatory for a remote native source.
// It acknowledges only the final sink's complete successful handoff for this
// exact chunk. A transport flush does not prove that a browser wrote a disk.
// Loss of this reply remains uncertain: close joins/clears the remote operation,
// while the original window remains charged. Direct/local readers need no ack.
type NativeResponseDeliveryAcknowledger interface {
	AcknowledgeNativeChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) error
}

type NativeResponseChunk struct {
	Bytes    []byte
	ReadWork int64
	// FinalVerified proves the exact selected native range, including the full
	// native checksum when the selected response contains the whole file.
	FinalVerified bool
}
type DownloadResponseSink interface {
	WriteChunk(context.Context, artifact.DownloadDeliveryLease, int64, []byte) (int64, error)
	Finish(context.Context) error
	Close()
}
type DownloadResponseSinkFactory interface {
	SelectDownloadResponse(artifact.NativeDownloadMetadata) (artifact.DownloadSelection, error)
	OpenDownloadResponse(context.Context, artifact.NativeDownloadMetadata, artifact.DownloadResponse) (DownloadResponseSink, error)
}

// ResponseRequest is supplied by authenticated ingress. HardUntil is the
// original request/session maximum, not the short current-identity observation.
// Range/conditional header strings are interpreted against verified metadata.
type DownloadResponseRequest struct {
	SessionID, ResponseID, OwnerID string
	HardUntil                      time.Time
}
