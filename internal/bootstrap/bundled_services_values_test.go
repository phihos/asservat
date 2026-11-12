package bootstrap

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundledServicesRejectInvalidSelectedInputsBeforeHook(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm is required")
	}
	for _, mode := range []string{"postgres-image", "identity-image", "store-image", "jdbc-option", "bundled-database-secret", "bootstrap-disabled", "workload-cluster"} {
		t.Run(mode, func(t *testing.T) {
			pg := map[string]any{"image": "registry.example/postgres@sha256:" + strings.Repeat("a", 64)}
			db := map[string]any{}
			kc := map[string]any{"hostname": "https://identity.example", "tlsSecretName": "identity-tls", "database": db}
			store := map[string]any{}
			b := smallServicesHelmBootstrap()
			values := map[string]any{"bootstrap": b, "services": map[string]any{"postgres": map[string]any{"provider": "bundled", "bundled": pg}, "identity": map[string]any{"provider": "keycloak", "keycloak": kc}, "objectStore": map[string]any{"provider": "seaweedfs", "seaweedfs": store}}}
			switch mode {
			case "postgres-image":
				pg["image"] = ""
			case "identity-image":
				kc["image"] = ""
			case "store-image":
				store["image"] = ""
			case "jdbc-option":
				db["name"] = "keycloak?sslmode=disable"
			case "bundled-database-secret":
				db["credentialsSecretName"] = "another-database-password"
			case "bootstrap-disabled":
				b["enabled"] = false
			case "workload-cluster":
				values["mode"] = "cluster"
			}
			raw, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "values.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			// Validate both the canonical schema and the producer's own refusal:
			// neither may defer the error until after preparation has run.
			for _, skip := range []bool{false, true} {
				args := []string{"template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", path}
				if skip {
					args = append(args, "--skip-schema-validation")
				}
				if output, err := exec.CommandContext(t.Context(), "helm", args...).CombinedOutput(); err == nil {
					t.Fatalf("invalid selected input rendered (schema skipped=%v): %s", skip, output)
				}
			}
		})
	}
}
