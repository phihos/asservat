package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
)

// Internal reservation input; identifiers and digests come from accepted
// authority/configuration, never an HTTP grant/actor/limit supplied by a caller.
type DownloadReservation struct {
	Session           artifact.DownloadSession
	IdempotencyDigest artifact.Digest
	Authority         artifact.DownloadAuthority
}
type DownloadSessions interface {
	ReserveDownload(context.Context, DownloadReservation) (artifact.DownloadSession, error)
	LookupDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error)
	BeginDownloadBatch(context.Context, string, artifact.DownloadAuthority, artifact.DownloadBatch) (audit.DownloadIntent, error)
	PermitDownloadBatch(context.Context, string, artifact.DownloadAuthority, string, int64) error
	PermitDownloadMetadata(context.Context, string, artifact.DownloadAuthority, string, int64) error
	FinishDownloadBatch(context.Context, string, string, int64, int64, bool, bool) (audit.DownloadOutcome, error)
	CancelDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error)
}
type DownloadAuditAcknowledger interface {
	AcknowledgeDownloadIntent(context.Context, audit.DownloadIntent, audit.Receipt) error
	AcknowledgeDownloadOutcome(context.Context, audit.DownloadOutcome, audit.Receipt) error
}

// Bootstrap must provide current ordinary/raw entitlement, protected retention,
// relay locality, identity policy and accepted version checks through this gate.
// Session existence, a successful decrypt or a testing fake cannot satisfy it.
type DownloadAuthorityGate interface {
	CheckDownload(context.Context, string, artifact.DownloadScope) (artifact.DownloadAuthority, error)
}
