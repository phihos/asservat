package providerconfig

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationProviderCleanupRecipeAndActualReadback(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"", "cleanup-open", "cleanup-verify", "cleanup-sign"} {
		t.Run(changed, func(t *testing.T) {
			f, in, original := configurationDeletionSigningSetupFixture(t, contracts.OwnerPublicTransit{}, map[int]ed25519.PublicKey{1: public}, 1)
			selection := configurationProviderSelectionOf(original.Profile)
			selection.CleanupAudit = contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: in.KeyService.AuditKey}
			r, err := ConfigurationProviderRecipeFor(in, selection, original.Profile.ServiceAccount, time.Now())
			if err != nil || len(r.Roles) != 6 || r.Profile.RecipeSHA256 == original.Profile.RecipeSHA256 {
				t.Fatal("cleanup recipe", err)
			}
			seen := map[string]bool{}
			for i, role := range r.Roles {
				if seen[role.Name] {
					t.Fatal("shared provider role", role.Name)
				}
				seen[role.Name] = true
				if i >= 2 {
					path := in.KeyService.AuditMount + "/decrypt/" + in.KeyService.AuditKey
					if i == 2 {
						path = in.KeyService.AuditMount + "/encrypt/" + in.KeyService.AuditKey
					}
					if i == 5 {
						path = selection.ContextDeletionSigning.Mount + "/sign/" + selection.ContextDeletionSigning.Key
					}
					want := []string{path, "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self"}
					slices.Sort(want)
					if !slices.Equal(configurationPolicyPaths(t, role), want) {
						t.Fatal("expanded cleanup capability", role.Purpose)
					}
				}
				f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
				f.responses["auth/"+selection.AuthMount+"/role/"+role.Name] = setupMap(t, role.Role)
				if role.Purpose == changed {
					f.responses["auth/"+selection.AuthMount+"/role/"+role.Name]["token_policies"] = json.RawMessage(`["default"]`)
				}
			}
			check, err := f.reader.VerifyConfiguration(context.Background(), in, r.Profile)
			if changed != "" {
				if err == nil {
					t.Fatal("expanded cleanup role accepted")
				}
				return
			}
			if err != nil || !check.Matches(in, r.Profile, time.Now()) {
				t.Fatal("real named provider readback", err)
			}
			selection.CleanupAudit.Key = "historical-alternative"
			if _, err := ConfigurationProviderRecipeFor(in, selection, original.Profile.ServiceAccount, time.Now()); err == nil {
				t.Fatal("alternative original key accepted")
			}
		})
	}
}
