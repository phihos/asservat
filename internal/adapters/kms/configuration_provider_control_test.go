package kms

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func configurationRole(purpose string) string { return "asservat-hub-worker-" + purpose }

// withConfigurationCleanup enables the four cleanup roles and the deletion
// signing key (ADR-205).
func withConfigurationCleanup(in *ConfigurationProviderInput) {
	in.Roles.CleanupWrap, in.Roles.CleanupOpen = configurationRole("cleanup-wrap"), configurationRole("cleanup-open")
	in.Roles.CleanupVerify, in.Roles.CleanupSign = configurationRole("cleanup-verify"), configurationRole("cleanup-sign")
	in.ContextDeletionSigning = contracts.OwnerPublicTransit{Mount: in.AuditMount, Key: contracts.ContextDeletionSigningKeyName(in.InstallationID)}
}

// change optionally extends the input (for example with ADR-205's context
// deletion signing key) before the control is built.
func configurationControlFixture(t *testing.T, purpose string, change ...func(*ConfigurationProviderInput)) (*ownerProviderControlFixture, ConfigurationProviderInput) {
	t.Helper()
	f := newOwnerProviderControlFixture(t)
	owner, _, _, _ := ownerProviderRecipeInput(t)
	in := ConfigurationProviderInput{InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, NamespaceUID: owner.Namespace.UID, OwnerSourceUID: "10000000-0000-4000-8000-000000000007",
		Namespace: owner.Namespace.Name, ServiceAccount: "asservat-hub-worker", Endpoint: f.server.URL, Roots: [][]byte{f.server.Certificate().Raw}, AuthMount: "owner-auth",
		AuditMount: "audit", AuditKey: "configuration", Roles: contracts.HubWorkerProviderRoles{AuditWrap: configurationRole("audit-wrap"), AuditUnwrap: configurationRole("audit-unwrap")},
		TokenFile: contracts.HubWorkerProviderTokenFile, AuditCredentialFile: contracts.HubWorkerAuditStorageFile}
	for _, c := range change {
		c(&in)
	}
	var err error
	f.control, err = newConfigurationProviderControl(in, configurationRole(purpose), f.server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.control.close)
	return f, in
}

func TestConfigurationControlUsesOnlyItsExactWorkerRole(t *testing.T) {
	for _, purpose := range []string{"audit-wrap", "audit-unwrap"} {
		t.Run(purpose, func(t *testing.T) {
			f, in := configurationControlFixture(t, purpose)
			if f.control.role != configurationRole(purpose) || f.control.account != in.ServiceAccount || f.control.accountUID != "" {
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
			for _, other := range []string{"", "bad/role", "role with space"} {
				if c, e := newConfigurationProviderControl(in, other, f.server.Client(), time.Now); e == nil || c != nil {
					t.Fatal("malformed role admitted", other)
				}
			}
		})
	}
}

func TestConfigurationControlRejectsAdditionalPolicyAndChangedAccount(t *testing.T) {
	for _, mode := range []string{"policy", "account", "unknown-login"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := configurationControlFixture(t, "audit-wrap")
			switch mode {
			case "policy":
				f.authChange = func(a *ownerProviderAuthReply) { a.Policies = append(a.Policies, "default") }
			case "account":
				f.authChange = func(a *ownerProviderAuthReply) {
					a.Metadata["service_account_name"] = "another-account"
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
