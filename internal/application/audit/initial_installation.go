package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"context"
)

type InitialInstallationWriter interface {
	WriteInitialInstallation(context.Context, value.InitialInstallation) (value.Receipt, error)
}
type InitialInstallationAcknowledgements interface {
	AcknowledgeInitialInstallation(context.Context, value.InitialInstallation, value.Receipt) error
}
