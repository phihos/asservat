package kubernetes

import (
	"crypto/ed25519"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextDeletionSectionValid checks the optional ADR-205 section's syntax:
// the evidence store and the pinned deletion signing key. It
// grants nothing; each purge, record and release is still checked in SQL.
func ContextDeletionSectionValid(v *contracts.ContextDeletionDeployment, now time.Time) bool {
	if v == nil {
		return true
	}
	s := v.Signing
	if providerconfig.ValidateStore(v.EvidenceStore, now) != nil ||
		!ownerBootstrapProviderName.MatchString(s.Mount) || !ownerBootstrapProviderName.MatchString(s.Key) || s.Version < 1 || s.Version > 2147483647 ||
		!identity.Text(s.KeyID, 128) || len(s.PublicKeys) < 1 || len(s.PublicKeys) > 16 || len(s.PublicKeys[s.KeyID]) != ed25519.PublicKeySize {
		return false
	}
	for id, key := range s.PublicKeys {
		if !identity.Text(id, 128) || len(key) != ed25519.PublicKeySize {
			return false
		}
	}
	return true
}
