package contracts

import "io"

const OwnerProviderAuthenticationFormat = "asservat-owner-kubernetes-auth/v1"
const OwnerProviderAuthenticationMaxBytes = 8192
const OwnerProviderTokenFile = "provider-auth.token"
const OwnerProviderAuditCredentialFile = "provider-audit-storage.json"
const OwnerProviderTokenTTLSeconds = 300
const OwnerProviderTokenMaxTTLSeconds = 900

// OwnerProviderAudience derives a fixed audience from separately validated
// installation and cluster UUIDs; the returned string grants no authority.
func OwnerProviderAudience(installationID, clusterID string) string {
	return "https://asservat." + installationID + "/owner-provider/" + clusterID
}

// Public, installation-owned selection. It contains no JWT, provider token,
// reviewer credential, secret-payload digest or caller-selectable purpose. This
// standalone profile is not recognized by the legacy owner deployment loader.
// Runtime selection must be introduced together with its receipt-bound loader.
type OwnerProviderAuthentication struct {
	Format            string                `json:"format"`
	AuthMount         string                `json:"authMount"`
	AuthMountAccessor string                `json:"authMountAccessor"`
	ServiceAccount    WorkerObjectReference `json:"serviceAccount"`
	AuditCredentials  WorkerObjectReference `json:"auditCredentials"`
	RecipeSHA256      string                `json:"recipeSHA256"`
}

func DecodeOwnerProviderAuthentication(r io.Reader) (OwnerProviderAuthentication, error) {
	return decodeClosedRPC[OwnerProviderAuthentication](r, OwnerProviderAuthenticationMaxBytes)
}
