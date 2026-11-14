package providerconfig

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// ADR-204 decision 7: the worker configuration observer seals with its own
// Transit key through the hub-worker's two audit purposes.
var workerAuditFixture = contracts.OwnerPublicTransit{Mount: "audit", Key: "worker-configuration"}

func configurationPolicyPaths(t *testing.T, r ConfigurationProviderRoleRecipe) []string {
	t.Helper()
	var acl ownerProviderACL
	if json.Unmarshal(r.Policy, &acl) != nil {
		t.Fatal("invalid generated policy")
	}
	var out []string
	for path, rule := range acl.Path {
		if !slices.Equal(rule.Capabilities, []string{"update"}) && !slices.Equal(rule.Capabilities, []string{"read"}) {
			t.Fatal("unexpected capability", path, rule.Capabilities)
		}
		out = append(out, path)
	}
	slices.Sort(out)
	return out
}

func TestConfigurationProviderRecipeExtendsBothAuditPurposesToWorkerAuditKey(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	base, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	selection.WorkerConfigurationAudit = workerAuditFixture
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil || ValidateConfigurationProviderAuthentication(in, r.Profile, now) != nil || r.Profile.WorkerConfigurationAudit != workerAuditFixture {
		t.Fatal("recipe with a worker configuration audit key failed", err)
	}
	if r.Profile.RecipeSHA256 == base.Profile.RecipeSHA256 {
		t.Fatal("digest does not bind the worker configuration audit key")
	}
	// Same two logins: the observer borrows their tokens.
	for i := range r.Roles {
		if r.Roles[i].Name != base.Roles[i].Name || r.Roles[i].Purpose != base.Roles[i].Purpose || !bytes.Equal(r.Roles[i].Role, base.Roles[i].Role) {
			t.Fatal("worker configuration audit changed a login")
		}
	}
	want := [2][]string{
		{"audit/encrypt/configuration", "audit/encrypt/worker-configuration", "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self"},
		{"audit/decrypt/configuration", "audit/decrypt/worker-configuration", "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self"},
	}
	for i, role := range r.Roles {
		if got := configurationPolicyPaths(t, role); !slices.Equal(got, want[i]) {
			t.Fatal("audit purpose policy is not exactly its effect on both keys", role.Purpose, got)
		}
	}
	// The digest binds the key both ways: adding it to a base profile or
	// removing it from an extended one is refused.
	for name, p := range map[string]contracts.ConfigurationProviderAuthentication{
		"added": func() contracts.ConfigurationProviderAuthentication {
			p := base.Profile
			p.WorkerConfigurationAudit = workerAuditFixture
			return p
		}(),
		"removed": func() contracts.ConfigurationProviderAuthentication {
			p := r.Profile
			p.WorkerConfigurationAudit = contracts.OwnerPublicTransit{}
			return p
		}(),
		"key": func() contracts.ConfigurationProviderAuthentication {
			p := r.Profile
			p.WorkerConfigurationAudit.Key = "other"
			return p
		}(),
		"mount": func() contracts.ConfigurationProviderAuthentication {
			p := r.Profile
			p.WorkerConfigurationAudit.Mount = "other"
			return p
		}(),
	} {
		if ValidateConfigurationProviderAuthentication(in, p, now) == nil {
			t.Fatal("profile accepted with a changed worker configuration audit key", name)
		}
	}
	for name, w := range map[string]contracts.OwnerPublicTransit{
		"configuration-key": {Mount: in.KeyService.AuditMount, Key: in.KeyService.AuditKey},
		"mount-only":        {Mount: "audit"},
		"key-only":          {Key: "worker-configuration"},
		"wildcard":          {Mount: "audit", Key: "*"},
		"path":              {Mount: "audit/keys", Key: "worker"},
		"sys":               {Mount: "sys", Key: "worker"},
		"auth":              {Mount: "auth", Key: "worker"},
	} {
		s := selection
		s.WorkerConfigurationAudit = w
		if _, err := ConfigurationProviderRecipeFor(in, s, account, now); err == nil {
			t.Fatal("invalid worker configuration audit key accepted", name)
		}
	}
}
