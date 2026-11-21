package authorization

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

// KeyMaterial stays inside the isolated service. Callers clear Payload after
// parsing. Configuration.Versions is populated from the actual private payload.
type KeyMaterial struct {
	Configuration value.LocalKeyConfiguration
	Payload       []byte
}
type KeyMaterialReader interface {
	ReadKeyMaterial(context.Context) (KeyMaterial, error)
}
type KeyConfigurationLedger interface {
	// Observe durably rejects rollback, changed version material and cross-purpose
	// reuse, checking current source freshness after blocking locks.
	ObserveLocalKeys(context.Context, value.LocalKeyConfiguration) (time.Time, error)
}

// KeyGeneration holds the immutable crypto backend for one accepted keyset.
// Guards return the same generation until a different keyset is accepted.
type KeyGeneration struct {
	Operations KeyOperationBackend
}
type KeyConfigurationGuard interface {
	CurrentKeyConfiguration(context.Context, value.KeyScope, string) (*KeyGeneration, time.Time, error)
}
