package providerconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// Without the key, the recipe preimage is byte-for-byte the one before
// ADR-204: the profile it hashes has exactly the original fields.
func TestConfigurationProviderRecipeDigestUnchangedWithoutWorkerAudit(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ownerProviderCanonical(struct {
		Format         string                             `json:"format"`
		InstallationID string                             `json:"installationID"`
		ClusterID      string                             `json:"clusterID"`
		Namespace      contracts.WorkerObjectReference    `json:"namespace"`
		FleetSource    contracts.WorkerObjectReference    `json:"fleetSource"`
		OwnerSource    contracts.WorkerObjectReference    `json:"ownerSource"`
		Kubernetes     contracts.OwnerProviderEndpoint    `json:"kubernetes"`
		KeyService     contracts.ConfigurationKeyService  `json:"keyService"`
		AuditStore     contracts.OwnerAuditStore          `json:"auditStore"`
		Profile        map[string]any                     `json:"profile"`
		Roles          [2]ConfigurationProviderRoleRecipe `json:"roles"`
	}{"asservat-configuration-provider-recipe/v1", in.InstallationID, in.ClusterID, in.Namespace, in.FleetSource, in.OwnerSource, in.Kubernetes, in.KeyService, in.AuditStore,
		map[string]any{"format": r.Profile.Format, "authMount": r.Profile.AuthMount, "authMountAccessor": r.Profile.AuthMountAccessor, "serviceAccount": r.Profile.ServiceAccount, "auditCredentials": r.Profile.AuditCredentials, "recipeSHA256": ""}, r.Roles})
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(legacy)
	if r.Profile.RecipeSHA256 != hex.EncodeToString(d[:]) {
		t.Fatal("recipe digest changed for a hub-worker without a worker configuration audit key")
	}
	for _, role := range r.Roles {
		if len(configurationPolicyPaths(t, role)) != 4 {
			t.Fatal("base policy widened")
		}
	}
	raw, err := json.Marshal(r.Profile)
	if err != nil || bytes.Contains(raw, []byte("workerConfigurationAudit")) {
		t.Fatal("zero worker configuration audit serialized")
	}
	for _, versioned := range []bool{false, true} {
		b, err := configurationProviderSetupArtifact(in, selection, account, now, versioned)
		if err != nil || bytes.Contains(b, []byte("workerConfigurationAudit")) || bytes.Contains(b, []byte("download-worker-configuration")) || bytes.Contains(b, []byte(workerAuditFixture.Key)) {
			t.Fatal("artifact changed without a worker configuration audit key", err)
		}
	}
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

func TestConfigurationPairArtifactCreatesWorkerAuditKeyAndPrefix(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	for _, worker := range []contracts.OwnerPublicTransit{workerAuditFixture, {Mount: "worker-audit", Key: "worker-configuration"}} {
		t.Run(worker.Mount, func(t *testing.T) {
			s := selection
			s.WorkerConfigurationAudit = worker
			r, err := ConfigurationProviderRecipeFor(in, s, account, now)
			if err != nil {
				t.Fatal(err)
			}
			b, err := ConfigurationProviderPairSetupArtifact(in, s, account, contracts.HubWorkerProviderInstalledLayout, now)
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Format       string                              `json:"format"`
				Apply        []configurationProviderSetupRequest `json:"apply"`
				Inspect      []string                            `json:"inspect"`
				AuditStorage struct {
					Prefixes   []string `json:"prefixes"`
					Operations []string `json:"operations"`
				} `json:"auditStorage"`
			}
			if json.Unmarshal(b, &v) != nil || v.Format != "asservat-configuration-provider-installed-setup/v3" || len(v.Apply) != 5 {
				t.Fatal("artifact shape changed", len(v.Apply))
			}
			for i, role := range r.Roles {
				var policy struct {
					Policy string `json:"policy"`
				}
				if v.Apply[2*i].Path != "sys/policies/acl/"+role.Name || json.Unmarshal(v.Apply[2*i].Body, &policy) != nil || policy.Policy != string(role.Policy) || !bytes.Equal(v.Apply[2*i+1].Body, role.Role) {
					t.Fatal("artifact policy is not the extended recipe policy")
				}
			}
			// The canonical artifact carries the key body in canonical form.
			key := v.Apply[4]
			body, err := ownerProviderCanonical(configurationTransitKey)
			if err != nil || key.Method != "POST" || key.Path != worker.Mount+"/keys/"+worker.Key || !bytes.Equal(key.Body, body) {
				t.Fatal("worker configuration audit key is not created exactly", key.Path)
			}
			wantInspect := []string{worker.Mount + "/keys/" + worker.Key}
			if worker.Mount != in.KeyService.AuditMount {
				wantInspect = []string{"sys/mounts/" + worker.Mount, worker.Mount + "/keys/" + worker.Key}
			}
			if len(v.Inspect) != 8+len(wantInspect) || !slices.Equal(v.Inspect[8:], wantInspect) {
				t.Fatal("inspection does not name the worker configuration audit key", v.Inspect)
			}
			if !slices.Equal(v.AuditStorage.Prefixes, []string{"hub-owner-configuration/v1/" + in.InstallationID + "/" + in.ClusterID + "/" + in.OwnerSource.UID + "/", "authority/v1/", "retention-acceptance/v1/", "lifecycle/v1/", "download-worker-configuration/v1/" + in.InstallationID + "/"}) ||
				!slices.Equal(v.AuditStorage.Operations, []string{"PutObject", "GetObject", "GetObjectVersion"}) {
				t.Fatal("audit storage lacks the worker configuration prefix", v.AuditStorage.Prefixes)
			}
			// The operator's applier accepts exactly these writes and reads.
			for _, request := range v.Apply {
				if !setupApplyPath(request.Path) {
					t.Fatal("applier refuses", request.Path)
				}
			}
			if _, err := setupInspectionPolicy(v.Inspect); err != nil {
				t.Fatal("inspection policy", err)
			}
		})
	}
	// The legacy unversioned profile has no versioned audit store.
	s := selection
	s.WorkerConfigurationAudit = workerAuditFixture
	if _, err := ConfigurationProviderSetupArtifact(in, s, account, now); err == nil {
		t.Fatal("legacy artifact accepted a worker configuration audit key")
	}
	// The installed artifact's selection must be the profile's.
	r, err := ConfigurationProviderRecipeFor(in, s, account, now)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = &r.Profile
	in.ProviderInputs = &contracts.ConfigurationWorkerInputProvenance{OperationID: "70000000-0000-4000-8000-000000000001"}
	in.Activation = &contracts.HubWorkerRuntimeActivation{WorkerLayout: contracts.HubWorkerProviderInstalledLayout}
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, s, account, now); err != nil {
		t.Fatal("installed artifact", err)
	}
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, selection, account, now); err == nil {
		t.Fatal("installed artifact dropped the profile's worker configuration audit key")
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
