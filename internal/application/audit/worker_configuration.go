package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

type WorkerConfigurationWriter interface {
	WriteWorkerConfiguration(context.Context, value.DownloadWorkerConfiguration) (audit.Receipt, error)
}
type WorkerConfigurationAcknowledgements interface {
	AcknowledgeWorkerConfiguration(context.Context, value.DownloadWorkerConfiguration, audit.Receipt) error
}
