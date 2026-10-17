package fleet

import (
	"context"

	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
)

// InitialRuntimeBridgeEffects belongs only to the separately authenticated
// post-activation installer. It holds current recovery and the exact original
// acknowledged activation across one bounded native journal/policy operation.
// It cannot activate SQL or supply native source/enforcement proof.
type InitialRuntimeBridgeEffects interface {
	InitialRuntimeBridgeRecord() (audit.InitialInstallation, audit.Receipt)
	WithInitialRuntimeBridge(context.Context, func(context.Context) error) error
}

// InitialRuntimeOwnerBridgeEffects additionally binds a fresh owner phase to
// the exact independently read fleet revision before any owner claim/effect.
// Its preflight is not SQL activation: current original recovery/activation
// locks and original source deadlines remain mandatory around the callback.
// Legacy bridge callers cannot silently substitute this stronger contract.
type InitialRuntimeOwnerBridgeEffects interface {
	InitialRuntimeBridgeEffects
	WithInitialRuntimeOwnerBridge(context.Context, fleet.Administration, func(context.Context) error) error
}
