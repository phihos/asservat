package providerconfig

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
)

// PublisherProviderPurposes are the publisher's three fixed provider roles
// (ADR-203 decision 3): audit wrap and unwrap on its own audit Transit key
// and verifier leaf signing on the worker PKI mount.
var PublisherProviderPurposes = [3]string{"audit-wrap", "audit-unwrap", "verifier-sign"}

type PublisherProviderRecipe struct {
	Profile contracts.PublisherProviderAuthentication
	Roles   [3]OwnerProviderRoleRecipe
}

// PublisherAuditKey is the publisher's own audit Transit key name; the
// publisher is the only reader of its verification audit.
func PublisherAuditKey(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-publisher-audit"
}
