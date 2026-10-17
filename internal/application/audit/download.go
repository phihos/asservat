package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	"context"
)

type DownloadWriter interface {
	WriteDownloadIntent(context.Context, audit.DownloadIntent) (audit.Receipt, error)
	WriteDownloadOutcome(context.Context, audit.DownloadOutcome) (audit.Receipt, error)
}
