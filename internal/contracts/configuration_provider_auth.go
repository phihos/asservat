package contracts

import "io"

const ConfigurationProviderAuthenticationFormat = "asservat-configuration-kubernetes-auth/v1"
const ConfigurationProviderAuthenticationMaxBytes = 8192
const ConfigurationProviderTokenFile = "configuration-provider-auth.token"
const ConfigurationProviderAuditCredentialFile = "configuration-audit-storage.json"
const ConfigurationProviderTokenTTLSeconds = 300
const ConfigurationProviderTokenMaxTTLSeconds = 900

// The dedicated projected audience cannot select another provider purpose.
func ConfigurationProviderAudience(installationID, clusterID string) string {
	return "https://asservat." + installationID + "/configuration-provider/" + clusterID
}

// ConfigurationProviderAuthentication is public original input. The actual
// protected producer, native workload, SQL recovery and finite provider leases
// remain separate; neither a decoded profile nor its digest grants authority.
//
// WorkerConfigurationAudit is the selection's optional worker configuration
// audit Transit key (ADR-204), carried so that the recipe can be recomputed
// from the profile alone; zero for a hub-worker without one.
// ContextDeletionSigning is likewise the selection's optional context
// deletion signing key (ADR-205).
type ConfigurationProviderAuthentication struct {
	Format                   string                `json:"format"`
	AuthMount                string                `json:"authMount"`
	AuthMountAccessor        string                `json:"authMountAccessor"`
	ServiceAccount           WorkerObjectReference `json:"serviceAccount"`
	AuditCredentials         WorkerObjectReference `json:"auditCredentials"`
	WorkerConfigurationAudit OwnerPublicTransit    `json:"workerConfigurationAudit,omitzero"`
	ContextDeletionSigning   OwnerPublicTransit    `json:"contextDeletionSigning,omitzero"`
	RecipeSHA256             string                `json:"recipeSHA256"`
}

func DecodeConfigurationProviderAuthentication(r io.Reader) (ConfigurationProviderAuthentication, error) {
	return decodeClosedRPC[ConfigurationProviderAuthentication](r, ConfigurationProviderAuthenticationMaxBytes)
}
