package providerconfig

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

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

// ADR-193: four purpose-separated roles bound to the federation account and
// audience, each confined to one provider path, with a binding digest.
func TestFederationProviderRecipeIsExactAndBound(t *testing.T) {
	in, sel := federationRecipeFixture()
	r, err := FederationProviderRecipeFor(in, sel)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateFederationProviderAuthentication(in, r.Profile, time.Now()) != nil {
		t.Fatal("recipe does not validate its own profile")
	}
	names := map[string]bool{}
	for i, role := range r.Roles {
		var body OwnerKubernetesAuthRole
		if role.Purpose != FederationProviderPurposes[i] || names[role.Name] || !strings.HasPrefix(role.Name, "asservat-federation-") || json.Unmarshal(role.Role, &body) != nil ||
			body.Audience != contracts.FederationProviderAudience(in.InstallationID, in.ClusterID) || len(body.Accounts) != 1 || body.Accounts[0] != sel.ServiceAccount.Name || !body.NoDefault {
			t.Fatal("role not bound to the federation account", role.Purpose)
		}
		names[role.Name] = true
		if strings.Count(string(role.Policy), `"capabilities"`) != 4 {
			t.Fatal("policy grants more than one effect path", role.Purpose)
		}
	}
	for name, mutate := range map[string]func(*contracts.FederationDeployment, *contracts.FederationProviderAuthentication){
		"other account": func(_ *contracts.FederationDeployment, s *contracts.FederationProviderAuthentication) {
			s.ServiceAccount.Name = "owner"
		},
		"token mount": func(_ *contracts.FederationDeployment, s *contracts.FederationProviderAuthentication) {
			s.AuthMount = "token"
		},
		"same PKI roles": func(c *contracts.FederationDeployment, _ *contracts.FederationProviderAuthentication) {
			c.KeyService.ServerRole = c.KeyService.ClientRole
		},
		"shared UID": func(_ *contracts.FederationDeployment, s *contracts.FederationProviderAuthentication) {
			s.AuditCredentials.UID = s.ServiceAccount.UID
		},
	} {
		c, s := federationRecipeFixture()
		mutate(&c, &s)
		if _, err := FederationProviderRecipeFor(c, s); err == nil {
			t.Fatal("accepted:", name)
		}
	}
	changed := in
	changed.KeyService.AuditKey = "other"
	if ValidateFederationProviderAuthentication(changed, r.Profile, time.Now()) == nil {
		t.Fatal("profile digest does not bind the key service paths")
	}
}
