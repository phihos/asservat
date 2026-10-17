package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
)

type DownloadWorkerWriter interface {
	WriteDownloadWorkerIntent(context.Context, authorization.DownloadWorkerIntent) (audit.Receipt, error)
}
type DownloadWorkerAcknowledgements interface {
	AcknowledgeDownloadWorkerIntent(context.Context, authorization.DownloadWorkerIntent, audit.Receipt) error
}
