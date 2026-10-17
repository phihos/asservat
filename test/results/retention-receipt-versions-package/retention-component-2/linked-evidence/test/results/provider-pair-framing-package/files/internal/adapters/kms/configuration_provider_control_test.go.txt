package kms

import (
	"context"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func configurationControlFixture(t *testing.T, purpose string) (*ownerProviderControlFixture, contracts.HubWorkerDeployment, contracts.ConfigurationProviderAuthentication) {
	t.Helper()
	f := newOwnerProviderControlFixture(t)
	owner, account, secret, now := ownerProviderRecipeInput(t)
	prefix := "asservat-" + strings.ReplaceAll(owner.InstallationID, "-", "")
	account.Name = prefix + "-worker"
	secret.Name = prefix + "-worker-providers"
	in := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, Namespace: owner.Namespace,
		FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: "10000000-0000-4000-8000-000000000006"}, OwnerSource: contracts.WorkerObjectReference{Name: prefix + "-owner-source", UID: "10000000-0000-4000-8000-000000000007"}, Kubernetes: owner.Kubernetes, Postgres: owner.Postgres, AuditStore: owner.AuditStore,
		KeyService: contracts.ConfigurationKeyService{Endpoint: f.server.URL, Roots: [][]byte{f.server.Certificate().Raw}, AuditMount: "audit", AuditKey: "configuration"}}
	// The fixture serves a fixed auth path. The worker still derives its own two
	// role names/account/audience; no owner role or production setup is reused.
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(in, contracts.ConfigurationProviderSelection{AuthMount: "owner-auth", AuthMountAccessor: "auth_kubernetes_original", AuditCredentials: secret}, account, now)
	if err != nil {
		t.Fatal(err)
	}
	f.control, err = newConfigurationProviderControl(in, recipe.Profile, purpose, f.server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.control.close)
	return f, in, recipe.Profile
}

func TestConfigurationControlUsesOnlyItsExactWorkerRole(t *testing.T) {
	for _, purpose := range []string{"audit-wrap", "audit-unwrap"} {
		t.Run(purpose, func(t *testing.T) {
			f, in, profile := configurationControlFixture(t, purpose)
			if !strings.HasPrefix(f.control.role, "asservat-configuration-") || f.control.account != profile.ServiceAccount.Name || f.control.accountUID != profile.ServiceAccount.UID {
				t.Fatal("worker adopted owner/provider identity")
			}
			credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
			if err != nil || credential == nil {
				t.Fatal("exact worker login/lookup failed", err)
			}
			defer credential.destroy()
			f.mu.Lock()
			logins, lookups := f.loginCalls, f.lookups
			f.mu.Unlock()
			if logins != 1 || lookups != 1 {
				t.Fatal("worker login repeated or skipped independent lookup")
			}
			for _, other := range []string{"server-sign", "client-sign", "root", "audit"} {
				if c, e := newConfigurationProviderControl(in, profile, other, f.server.Client(), time.Now); e == nil || c != nil {
					t.Fatal("other purpose admitted", other)
				}
			}
		})
	}
}

func TestConfigurationControlRejectsAdditionalPolicyAndChangedAccount(t *testing.T) {
	for _, mode := range []string{"policy", "account", "unknown-login"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _ := configurationControlFixture(t, "audit-wrap")
			switch mode {
			case "policy":
				f.authChange = func(a *ownerProviderAuthReply) { a.Policies = append(a.Policies, "default") }
			case "account":
				f.authChange = func(a *ownerProviderAuthReply) {
					a.Metadata["service_account_uid"] = "10000000-0000-4000-8000-000000000099"
				}
			case "unknown-login":
				f.mode = mode
			}
			c, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
			if err == nil || c != nil {
				t.Fatal("changed or uncertain provider reply produced credential")
			}
			f.mu.Lock()
			logins, lookups := f.loginCalls, f.lookups
			f.mu.Unlock()
			if logins != 1 || lookups != 0 {
				t.Fatal("failed login repeated or searched for unknown token")
			}
		})
	}
}
