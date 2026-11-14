package providerconfig

import (
	"crypto/ed25519"
	"time"
)

// ConfigurationSetupCheck can only be produced by the concrete installer
// reader. It is finite provider readback, not Kubernetes custody, SQL recovery,
// backend capability, runtime authorization or an atomic fence against later
// changes by the trusted provider administrator.
type ConfigurationSetupCheck struct {
	binding           [32]byte
	observedAt, until time.Time
	signing           *ContextDeletionSigningReadback
}

// ContextDeletionSigningReadback is the context deletion signing key as the
// configuration readback observed it (ADR-205 decision 6): its latest
// version and the public key of each version Transit returned, for the
// installer to pin. It is an observation, never signing authority.
type ContextDeletionSigningReadback struct {
	Mount, Key string
	Version    int
	PublicKeys map[int]ed25519.PublicKey
}
