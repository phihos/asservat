package providerconfig

import (
	"asservat.local/asservat/internal/contracts"
)

func federationRecipeFixture() (contracts.FederationDeployment, contracts.FederationProviderAuthentication) {
	installation := "10000000-0000-4000-8000-000000000001"
	in := contracts.FederationDeployment{Format: contracts.FederationDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000000002",
		KeyService: contracts.FederationKeyService{Endpoint: "https://bao.example", AuditMount: "transit", AuditKey: "federation-audit", PKIMount: "connector-pki", ClientRole: "connector-client", ServerRole: "connector-server"}}
	sel := contracts.FederationProviderAuthentication{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1",
		Namespace:        contracts.WorkerObjectReference{Name: "asservat", UID: "10000000-0000-4000-8000-000000000003"},
		ServiceAccount:   contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(installation), UID: "10000000-0000-4000-8000-000000000004"},
		AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: "10000000-0000-4000-8000-000000000005"}}
	return in, sel
}
