package providerconfig

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ValidateOwner checks the fixed owner's public audit and paired PKI inputs
// before immutable projection. Provider capability and current authority remain
// independent runtime prerequisites; no remote effect is performed here.
func ValidateOwner(k contracts.OwnerProviderEndpoint, p contracts.OwnerPostgresEndpoint, a contracts.OwnerAuditStore, key contracts.OwnerKeyService, now time.Time) error {
	audit := contracts.ConfigurationKeyService{Endpoint: key.Endpoint, Roots: key.Roots, AuditMount: key.AuditMount, AuditKey: key.AuditKey}
	if Validate(k, p, a, audit, now) != nil || !providerName.MatchString(key.PKIMount) || !providerName.MatchString(key.ServerRole) || !providerName.MatchString(key.ClientRole) || key.ServerRole == key.ClientRole || key.AuditMount == key.PKIMount {
		return cfg.ErrInvalid
	}
	return nil
}
