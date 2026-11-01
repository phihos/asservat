package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestInstallerProviderRecipeHistoryBindsInputsWithoutEmittingCredential(t *testing.T) {
	dir := t.TempDir()
	id := "10000000-0000-4000-8000-000000000002"
	cluster := "10000000-0000-4000-8000-000000000003"
	epoch := "10000000-0000-4000-8000-000000000005"
	secret := strings.Repeat("C", 42) + "A"
	offer := map[string]any{"format": "asservat-regional-offer/v1", "installationID": id, "permissionRootID": id, "issuerEpoch": epoch, "evidenceStore": map[string]any{"bucket": "history-fixture"}}
	binding := map[string]any{"format": "asservat-bootstrap-secret/v1", "installationID": id, "bootstrapID": id, "clusterID": cluster, "peerID": id, "issuerEpoch": epoch, "deliveryProfile": "regional-installer", "requestSHA256": strings.Repeat("1", 64), "notBefore": "2026-10-27T00:00:00Z", "notAfter": "2026-10-27T00:05:00Z"}
	offerPath, bootstrapPath := filepath.Join(dir, "offer.json"), filepath.Join(dir, "bootstrap.json")
	write := func(path string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(offerPath, offer)
	write(bootstrapPath, map[string]any{"binding": binding, "secret": secret})
	var out bytes.Buffer
	args := []string{"--history-offer", offerPath, "--history-bootstrap", bootstrapPath}
	if e := RunInstallerProviderRecipe(context.Background(), args, &out); e != nil {
		t.Fatal(e)
	}
	var result struct {
		History struct {
			Prefix  string          `json:"prefix"`
			Actions []string        `json:"seaweedIdentityActions"`
			Policy  json.RawMessage `json:"s3BucketPolicy"`
		} `json:"regionalHistory"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.History.Prefix != "history/v1/"+id+"/"+cluster+"/" || len(result.History.Actions) != 3 || len(result.History.Policy) == 0 {
		t.Fatal("history proposal lost exact installed scope", out.String())
	}
	if strings.Contains(out.String(), secret) || strings.Contains(out.String(), "requestSHA256") {
		t.Fatal("bootstrap credential leaked")
	}
	for _, bad := range [][]string{{"--history-offer", offerPath}, {"--history-bootstrap", bootstrapPath}} {
		out.Reset()
		if RunInstallerProviderRecipe(context.Background(), bad, &out) == nil || out.Len() != 0 {
			t.Fatal("partial proposal emitted")
		}
	}
	binding["installationID"] = cluster
	write(bootstrapPath, map[string]any{"binding": binding, "secret": secret})
	out.Reset()
	if RunInstallerProviderRecipe(context.Background(), args, &out) == nil || out.Len() != 0 {
		t.Fatal("different installation proposal emitted")
	}
}
