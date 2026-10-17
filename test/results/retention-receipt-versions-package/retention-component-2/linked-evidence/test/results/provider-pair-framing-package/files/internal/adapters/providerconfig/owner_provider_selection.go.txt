package providerconfig

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ValidateOwnerProviderSelection checks the fixed pre-resource public choice.
// Current native Secret identity and provider recipe capability are separate
// checks; this function never reads credentials or makes an external call.
func ValidateOwnerProviderSelection(installationID string, p contracts.OwnerProviderSelection) error {
	if !authorization.UUID(installationID) || !providerName.MatchString(p.AuthMount) || p.AuthMount == "token" || !providerName.MatchString(p.AuthMountAccessor) || !authorization.UUID(p.AuditCredentials.UID) || p.AuditCredentials.Name != contracts.OwnerProviderAuditSecretName(installationID) {
		return cfg.ErrInvalid
	}
	return nil
}
