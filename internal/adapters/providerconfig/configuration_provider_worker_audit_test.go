package providerconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

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

func configurationWorkerAuditSetupFixture(t *testing.T, worker contracts.OwnerPublicTransit) (*setupFixture, contracts.HubWorkerDeployment, ConfigurationProviderRecipe) {
	t.Helper()
	f, in, base := configurationSetupFixture(t)
	selection := contracts.ConfigurationProviderSelection{AuthMount: base.Profile.AuthMount, AuthMountAccessor: base.Profile.AuthMountAccessor, AuditCredentials: base.Profile.AuditCredentials, WorkerConfigurationAudit: worker}
	recipe, err := ConfigurationProviderRecipeFor(in, selection, base.Profile.ServiceAccount, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range recipe.Roles {
		f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
	}
	if worker.Mount != in.KeyService.AuditMount {
		f.responses["sys/mounts/"+worker.Mount] = setupMap(t, map[string]any{"type": "transit"})
	}
	f.responses[worker.Mount+"/keys/"+worker.Key] = setupMap(t, map[string]any{
		"name": worker.Key, "type": "aes256-gcm96", "derived": false, "exportable": false,
		"allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true,
		"latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0,
	})
	return f, in, recipe
}

func TestConfigurationSetupVerifiesWorkerAuditKeyAndExtendedPolicies(t *testing.T) {
	for _, worker := range []contracts.OwnerPublicTransit{workerAuditFixture, {Mount: "worker-audit", Key: "worker-configuration"}} {
		f, in, recipe := configurationWorkerAuditSetupFixture(t, worker)
		reads := int32(9)
		if worker.Mount != in.KeyService.AuditMount {
			reads = 10
		}
		check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
		if err != nil || !check.Matches(in, recipe.Profile, time.Now()) || f.requests.Load() != reads {
			t.Fatal("worker configuration audit readback failed", worker.Mount, err, f.requests.Load())
		}
	}
	for _, mode := range []string{"base-policy", "exportable-key", "other-key", "missing-key", "mount-type"} {
		t.Run(mode, func(t *testing.T) {
			worker := contracts.OwnerPublicTransit{Mount: "worker-audit", Key: "worker-configuration"}
			f, in, recipe := configurationWorkerAuditSetupFixture(t, worker)
			key := f.responses[worker.Mount+"/keys/"+worker.Key]
			switch mode {
			case "base-policy":
				// A provider still holding the policy without the worker key.
				p := recipe.Profile
				base, err := ConfigurationProviderRecipeFor(in, contracts.ConfigurationProviderSelection{AuthMount: p.AuthMount, AuthMountAccessor: p.AuthMountAccessor, AuditCredentials: p.AuditCredentials}, p.ServiceAccount, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				f.responses["sys/policies/acl/"+base.Roles[0].Name] = setupMap(t, map[string]any{"name": base.Roles[0].Name, "policy": string(base.Roles[0].Policy)})
			case "exportable-key":
				key["exportable"] = json.RawMessage(`true`)
			case "other-key":
				key["name"] = json.RawMessage(`"configuration"`)
			case "missing-key":
				f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/v1/"+worker.Mount+"/keys/"+worker.Key {
						return false
					}
					w.WriteHeader(http.StatusNotFound)
					return true
				}
			case "mount-type":
				f.responses["sys/mounts/"+worker.Mount] = setupMap(t, map[string]any{"type": "kv"})
			}
			check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
			if !errors.Is(err, ErrSetupUnavailable) || check != (ConfigurationSetupCheck{}) {
				t.Fatal("changed worker configuration audit setup accepted", err)
			}
		})
	}
}
