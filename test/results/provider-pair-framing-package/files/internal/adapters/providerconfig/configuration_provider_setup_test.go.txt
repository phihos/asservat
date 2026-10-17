package providerconfig

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// Reuse the concrete pinned-TLS SetupReader fixture. Its responses are
// explicitly synthetic provider configuration, never production setup proof.
func configurationSetupFixture(t *testing.T) (*setupFixture, contracts.HubWorkerDeployment, ConfigurationProviderRecipe) {
	t.Helper()
	f := newSetupFixture(t)
	in, selection, account, now := configurationProviderRecipeFixture(t)
	in.KeyService.Endpoint, in.KeyService.Roots = f.in.KeyService.Endpoint, f.roots
	recipe, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	f.responses = map[string]map[string]json.RawMessage{}
	f.responses["sys/mounts/auth/"+selection.AuthMount] = setupMap(t, map[string]any{
		"type": "kubernetes", "accessor": selection.AuthMountAccessor,
		"config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 2764800, "token_type": "default-service"},
	})
	var ca strings.Builder
	for _, der := range in.Kubernetes.Roots {
		ca.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	f.responses["auth/"+selection.AuthMount+"/config"] = setupMap(t, map[string]any{
		"kubernetes_host": in.Kubernetes.Endpoint, "kubernetes_ca_cert": ca.String(),
		"disable_local_ca_jwt": true, "token_reviewer_jwt_set": true, "pem_keys": []string{},
	})
	f.responses["sys/mounts/"+in.KeyService.AuditMount] = setupMap(t, map[string]any{"type": "transit"})
	f.responses[in.KeyService.AuditMount+"/keys/"+in.KeyService.AuditKey] = setupMap(t, map[string]any{
		"name": in.KeyService.AuditKey, "type": "aes256-gcm96", "derived": false, "exportable": false,
		"allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true,
		"latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0,
	})
	for _, role := range recipe.Roles {
		f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
		f.responses["auth/"+selection.AuthMount+"/role/"+role.Name] = setupMap(t, role.Role)
	}
	return f, in, recipe
}

func TestConfigurationSetupUsesOnlyEightNamedReadPathsAndWholeInput(t *testing.T) {
	f, in, recipe := configurationSetupFixture(t)
	start := time.Now()
	check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
	if err != nil || !check.Matches(in, recipe.Profile, time.Now()) || f.requests.Load() != 8 ||
		check.ObservedAt().Before(start) || check.FreshUntil().After(check.ObservedAt().Add(5*time.Second)) {
		t.Fatal("exact two-purpose readback failed", err, f.requests.Load())
	}
	changed := in
	changed.LeaderLease.UID = "10000000-0000-4000-8000-000000000009"
	if check.Matches(changed, recipe.Profile, time.Now()) || check.Matches(in, recipe.Profile, check.FreshUntil()) || (ConfigurationSetupCheck{}).Matches(in, recipe.Profile, time.Now()) {
		t.Fatal("whole-input change, expiry or zero check accepted")
	}
	selection := contracts.ConfigurationProviderSelection{AuthMount: recipe.Profile.AuthMount, AuthMountAccessor: recipe.Profile.AuthMountAccessor, AuditCredentials: recipe.Profile.AuditCredentials}
	raw, err := ConfigurationProviderSetupArtifact(in, selection, recipe.Profile.ServiceAccount, time.Now())
	var artifact struct {
		Inspect []string `json:"inspect"`
	}
	if err != nil || json.Unmarshal(raw, &artifact) != nil || len(artifact.Inspect) != 8 {
		t.Fatal("artifact read scope", err)
	}
	for _, path := range artifact.Inspect {
		if _, ok := f.responses[path]; !ok || strings.ContainsAny(path, "*+") || strings.HasPrefix(path, "sys/auth/") {
			t.Fatal("artifact and actual verifier scope differ", path)
		}
	}
}

func TestConfigurationSetupRejectsEffectiveScopeChanges(t *testing.T) {
	for _, mode := range []string{"mount-accessor", "reviewer-absent", "local-reviewer", "wrong-api", "key-export", "old-key-loss", "role-account", "role-audience", "extra-token-policy", "unbounded-token", "future-role-field", "expanded-policy", "forced-batch", "negative-mount-ttl"} {
		t.Run(mode, func(t *testing.T) {
			f, in, recipe := configurationSetupFixture(t)
			mount := f.responses["sys/mounts/auth/"+recipe.Profile.AuthMount]
			auth := f.responses["auth/"+recipe.Profile.AuthMount+"/config"]
			key := f.responses[in.KeyService.AuditMount+"/keys/"+in.KeyService.AuditKey]
			role := f.responses["auth/"+recipe.Profile.AuthMount+"/role/"+recipe.Roles[0].Name]
			switch mode {
			case "mount-accessor":
				mount["accessor"] = json.RawMessage(`"replacement"`)
			case "reviewer-absent":
				auth["token_reviewer_jwt_set"] = json.RawMessage(`false`)
			case "local-reviewer":
				auth["disable_local_ca_jwt"] = json.RawMessage(`false`)
			case "wrong-api":
				auth["kubernetes_host"] = json.RawMessage(`"https://foreign.invalid"`)
			case "key-export":
				key["exportable"] = json.RawMessage(`true`)
			case "old-key-loss":
				key["min_decryption_version"] = json.RawMessage(`2`)
			case "role-account":
				role["bound_service_account_names"] = json.RawMessage(`["other"]`)
			case "role-audience":
				role["audience"] = json.RawMessage(`"owner-provider"`)
			case "extra-token-policy":
				role["token_policies"] = json.RawMessage(`["default"]`)
			case "unbounded-token":
				role["token_explicit_max_ttl"] = json.RawMessage(`0`)
			case "future-role-field":
				role["future_allow_anything"] = json.RawMessage(`true`)
			case "expanded-policy":
				f.responses["sys/policies/acl/"+recipe.Roles[0].Name]["policy"] = json.RawMessage(`"{\"path\":{\"*\":{\"capabilities\":[\"root\"]}}}"`)
			case "forced-batch":
				mount["config"] = json.RawMessage(`{"default_lease_ttl":0,"max_lease_ttl":2764800,"token_type":"batch"}`)
			case "negative-mount-ttl":
				mount["config"] = json.RawMessage(`{"default_lease_ttl":-1,"max_lease_ttl":2764800,"token_type":"service"}`)
			}
			check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
			if !errors.Is(err, ErrSetupUnavailable) || check != (ConfigurationSetupCheck{}) {
				t.Fatal("changed effective setup accepted", err)
			}
		})
	}
}

func TestConfigurationSetupLastReadRetainsOriginalCallerDeadline(t *testing.T) {
	f, in, recipe := configurationSetupFixture(t)
	last := "/v1/auth/" + recipe.Profile.AuthMount + "/role/" + recipe.Roles[1].Name
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != last {
			return false
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	check, err := f.reader.VerifyConfiguration(ctx, in, recipe.Profile)
	if !errors.Is(err, ErrSetupUnavailable) || check != (ConfigurationSetupCheck{}) || f.requests.Load() != 8 || ctx.Err() == nil {
		t.Fatal("last read renewed original caller interval or retried", err, f.requests.Load())
	}
}
