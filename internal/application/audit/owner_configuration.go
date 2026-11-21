package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"context"
)

type OwnerConfigurationWriter interface {
	WriteOwnerConfiguration(context.Context, fleet.OwnerConfiguration) (audit.Receipt, error)
}
