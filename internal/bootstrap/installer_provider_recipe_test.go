package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestInstallerProviderRecipeIsFinitePublicAndDeterministic(t *testing.T) {
	var first, second bytes.Buffer
	for _, out := range []*bytes.Buffer{&first, &second} {
		if err := RunInstallerProviderRecipe(context.Background(), nil, out); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("public prerequisites changed between reads")
	}
	var output struct {
		Policies map[string]string `json:"policies"`
		Roles    map[string]struct {
			Policies  []string `json:"allowed_policies"`
			MaxTTL    int      `json:"token_explicit_max_ttl"`
			Renewable bool     `json:"renewable"`
			NoDefault bool     `json:"token_no_default_policy"`
		} `json:"token_roles"`
		Issuer struct {
			TTL       string `json:"ttl"`
			MaxTTL    string `json:"explicit_max_ttl"`
			NoParent  bool   `json:"no_parent"`
			Renewable bool   `json:"renewable"`
		} `json:"issuer_token_request"`
	}
	if json.Unmarshal(first.Bytes(), &output) != nil || len(output.Policies) != 3 || len(output.Roles) != 2 || output.Issuer.TTL != "15m" || output.Issuer.MaxTTL != "15m" || output.Issuer.NoParent || output.Issuer.Renewable {
		t.Fatal("recipe weakened original finite profile")
	}
	for _, role := range output.Roles {
		if len(role.Policies) != 1 || role.MaxTTL != 900 || role.Renewable || !role.NoDefault {
			t.Fatal("role broadened")
		}
	}
	for _, forbidden := range []string{"client_token", "password", "materialUID", "sudo", "*"} {
		if strings.Contains(first.String(), forbidden) {
			t.Fatal("recipe gained credential or broad privilege", forbidden)
		}
	}
	for _, args := range [][]string{{"--issuer-policy", "root"}, {"--wrap-policy", "asservat-install-issuer"}, {"--audit-key", "../other"}, {"--token", "secret"}} {
		var out bytes.Buffer
		if RunInstallerProviderRecipe(context.Background(), args, &out) == nil || out.Len() != 0 {
			t.Fatal("invalid prerequisites emitted", args)
		}
	}
}
