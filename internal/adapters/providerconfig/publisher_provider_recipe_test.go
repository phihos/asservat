package providerconfig

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func publisherRecipeFixture() (contracts.PublisherDeployment, contracts.PublisherProviderAuthentication) {
	installation := "10000000-0000-4000-8000-000000002030"
	namespace := contracts.WorkerObjectReference{Name: "asservat", UID: "10000000-0000-4000-8000-000000002032"}
	provider := [][]byte{{1, 2, 3}}
	in := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000002031", PermissionRootID: "10000000-0000-4000-8000-000000002034", Namespace: namespace,
		AuditKeys: contracts.PublisherTransit{Endpoint: "https://bao.example", Roots: provider, Mount: "transit", Key: PublisherAuditKey(installation)},
		Verifier:  contracts.PublisherVerifier{Endpoint: "https://bao.example", Roots: provider, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(installation)}}
	sel := contracts.PublisherProviderAuthentication{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1", Namespace: namespace,
		ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(installation), UID: "10000000-0000-4000-8000-000000002033"}}
	return in, sel
}

func publisherSetupFixture(t *testing.T, f *setupFixture) contracts.PublisherDeployment {
	t.Helper()
	p := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: f.in.InstallationID, ClusterID: f.in.ClusterID, PermissionRootID: f.in.PermissionRootID, Namespace: f.in.Namespace, AuditStore: f.in.AuditStore,
		AuditKeys: contracts.PublisherTransit{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, Mount: f.in.KeyService.AuditMount, Key: PublisherAuditKey(f.in.InstallationID)},
		Evidence:  contracts.PublisherEvidence{Endpoint: "https://evidence.invalid", Roots: f.roots, Region: "test", Bucket: "evidence", StoreID: "10000000-0000-4000-8000-000000002035"},
		Verifier:  contracts.PublisherVerifier{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(f.in.InstallationID), IssuerRoots: f.roots}}
	r, err := PublisherProviderRecipeFor(p, contracts.PublisherProviderAuthentication{AuthMount: f.profile.AuthMount, AuthMountAccessor: f.profile.AuthMountAccessor, Namespace: f.in.Namespace,
		ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(f.in.InstallationID), UID: "10000000-0000-4000-8000-000000002036"}})
	if err != nil {
		t.Fatal(err)
	}
	p.ProviderAuthentication = r.Profile
	return p
}
