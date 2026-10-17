package contracts

import "strings"

// OwnerProviderSelection binds the original public provider choice before
// resource creation. The actual owner ServiceAccount UID and four-purpose
// recipe derive later from the original account receipt. No credential or
// provider capability is established by this value.
type OwnerProviderSelection struct {
	AuthMount         string                `json:"authMount"`
	AuthMountAccessor string                `json:"authMountAccessor"`
	AuditCredentials  WorkerObjectReference `json:"auditCredentials"`
}

// OwnerProviderAuditSecretName is distinct from the immutable SQL identity
// projection. Callers validate the installation UUID before deriving the name.
func OwnerProviderAuditSecretName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-owner-audit"
}
