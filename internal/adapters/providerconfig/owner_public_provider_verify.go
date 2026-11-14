package providerconfig

import (
	"time"

	"asservat.local/asservat/internal/contracts"
)

// OwnerPublicReadback is what a promoted owner input pins from the applied
// provider (ADR-194 step 6): the work-signing key's latest version and public
// key, and the worker PKI issuer as the worker trust root.
type OwnerPublicReadback struct {
	Signing     contracts.OwnerPublicSigning
	WorkerRoots [][]byte
	Until       time.Time
}
