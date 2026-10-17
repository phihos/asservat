package fleet

import (
	"context"

	"asservat.local/asservat/internal/domain/audit"
)

// InitialRuntimeBridgeEffects belongs only to the separately authenticated
// post-activation installer. It holds current recovery and the exact original
// acknowledged activation across one bounded native journal/policy operation.
// It cannot activate SQL or supply native source/enforcement proof.
type InitialRuntimeBridgeEffects interface {
	InitialRuntimeBridgeRecord() (audit.InitialInstallation, audit.Receipt)
	WithInitialRuntimeBridge(context.Context, func(context.Context) error) error
}
