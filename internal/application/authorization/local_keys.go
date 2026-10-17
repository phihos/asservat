package authorization

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// KeyMaterial stays inside the isolated service. Callers clear Payload after
// parsing. Configuration.Versions is populated from the actual private payload.
type KeyMaterial struct {
	Configuration          value.LocalKeyConfiguration
	Payload, SigningPublic []byte
}
type KeyMaterialReader interface {
	ReadKeyMaterial(context.Context) (KeyMaterial, error)
}
type KeyConfigurationLedger interface {
	// Observe durably rejects rollback, changed version material and cross-purpose
	// reuse, checking current recovery and source freshness after blocking locks.
	ObserveLocalKeys(context.Context, value.LocalKeyConfiguration) (time.Time, error)
}
type KeyConfigurationGuard interface {
	CurrentKeyConfiguration(context.Context, value.KeyScope, string) (time.Time, error)
}
