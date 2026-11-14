package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// This checks the actual chart producer against the preparation output and
// Keycloak's startup inputs. It is not a running Keycloak qualification.
func TestSmallKeycloakHelmUsesPreparedMaterialAndIndependentDatabase(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("Helm is required")
	}
	kc := map[string]any{"image": contracts.SmallKeycloakImage, "hostname": "https://identity.example:30443", "realm": "asservat", "tlsSecretName": "operator-identity-tls", "mcpRedirectURIs": []string{"http://127.0.0.1:42000/callback"}, "database": map[string]any{"host": "", "port": 5432, "name": "keycloak", "user": "keycloak", "credentialsSecretName": "", "rootsSecretName": "", "maxConnections": 5}, "service": map[string]any{"type": "NodePort", "nodePort": 30443}, "resources": map[string]any{"requests": map[string]string{"cpu": "100m", "memory": "512Mi"}, "limits": map[string]string{"cpu": "1", "memory": "1Gi"}}}
	values := smallServicesHelmValues(map[string]any{"identity": map[string]any{"provider": "keycloak", "keycloak": kc}, "postgres": map[string]any{"provider": "bundled", "bundled": map[string]any{"image": "registry.example/postgres@sha256:" + strings.Repeat("b", 64)}}})
	render := func() ([]byte, error) {
		t.Helper()
		body, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "values.json")
		if err = os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		ctx, end := context.WithTimeout(t.Context(), 15*time.Second)
		defer end()
		return exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "installation", "--kube-version", "1.35.0", "-f", "testdata/helm-fixture.yaml", "-f", path).CombinedOutput()
	}
	read := func(raw []byte) (*apps.Deployment, *core.Service) {
		t.Helper()
		var deployment *apps.Deployment
		var service *core.Service
		decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
		for {
			var doc json.RawMessage
			if err := decoder.Decode(&doc); err == io.EOF {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			var head struct {
				Kind     string
				Metadata struct{ Name string }
			}
			if json.Unmarshal(doc, &head) != nil {
				t.Fatal("invalid chart JSON")
			}
			if head.Metadata.Name != "trial-keycloak" {
				continue
			}
			switch head.Kind {
			case "Deployment":
				deployment = &apps.Deployment{}
				if json.Unmarshal(doc, deployment) != nil {
					t.Fatal("deployment decode")
				}
			case "Service":
				service = &core.Service{}
				if json.Unmarshal(doc, service) != nil {
					t.Fatal("service decode")
				}
			}
		}
		return deployment, service
	}
	raw, err := render()
	if err != nil {
		t.Fatalf("actual chart: %v\n%s", err, raw)
	}
	d, s := read(raw)
	if d == nil || s == nil {
		t.Fatal("selected Keycloak not produced")
	}
	container := d.Spec.Template.Spec.Containers[0]
	if container.Image != contracts.SmallKeycloakImage || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Spec.Strategy.Type != apps.RecreateDeploymentStrategyType || d.Spec.Template.Spec.AutomountServiceAccountToken == nil || *d.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("changed isolated single-instance provider")
	}
	env := map[string]core.EnvVar{}
	for _, v := range container.Env {
		env[v.Name] = v
	}
	if env["KC_DB_POOL_MAX_SIZE"].Value != "5" || env["KC_DB_URL"].Value != "jdbc:postgresql://trial-postgres.installation.svc:5432/keycloak?sslmode=verify-full&sslrootcert=/opt/keycloak/db/ca.crt" {
		t.Fatal("database producer disagrees with private role/certificate inputs")
	}
	checkPoolRecovery := func(container core.Container) {
		t.Helper()
		settings := map[string]core.EnvVar{}
		for _, item := range container.Env {
			settings[item.Name] = item
		}
		for name, want := range map[string]string{
			"KC_DB_POOL_INITIAL_SIZE": "1", "KC_DB_POOL_MIN_SIZE": "1", "KC_DB_POOL_MAX_SIZE": "5",
			"QUARKUS_DATASOURCE_JDBC_FOREGROUND_VALIDATION_INTERVAL": "5s",
			"QUARKUS_DATASOURCE_JDBC_VALIDATION_QUERY_TIMEOUT":       "2s",
		} {
			if settings[name].Value != want || settings[name].ValueFrom != nil {
				t.Fatalf("pinned Keycloak pool recovery setting %s: got %q, want %q", name, settings[name].Value, want)
			}
		}
		if settings["QUARKUS_DATASOURCE_JDBC_VALIDATE_ON_BORROW"].Name != "" {
			t.Fatal("pool recovery must retain idle validation without validating every checkout")
		}
	}
	checkPoolRecovery(container)
	password := env["KCRAW_DB_PASSWORD"]
	if password.ValueFrom == nil || password.ValueFrom.SecretKeyRef == nil || password.ValueFrom.SecretKeyRef.Name != "trial-postgres-state" || password.ValueFrom.SecretKeyRef.Key != "keycloak-password" || env["KC_DB_PASSWORD"].Name != "" {
		t.Fatal("operator database password must bypass Keycloak configuration interpolation")
	}
	if env["KC_ASSERVAT_CONSOLE_SECRET"].ValueFrom.SecretKeyRef.Name != "trial-keycloak-state" || env["KC_ASSERVAT_CONSOLE_SECRET"].ValueFrom.SecretKeyRef.Key != contracts.SmallKeycloakConsoleSecret || env["KC_BOOTSTRAP_ADMIN_PASSWORD"].Value != "" || env["KC_BOOTSTRAP_ADMIN_PASSWORD"].ValueFrom.SecretKeyRef.Key != contracts.SmallKeycloakAdminPassword {
		t.Fatal("provider lost retained secret references")
	}
	if s.Spec.Type != core.ServiceTypeNodePort || len(s.Spec.Ports) != 1 || s.Spec.Ports[0].NodePort != 30443 || s.Spec.Ports[0].Port != 8443 || !strings.Contains(strings.Join(container.Args, " "), "--http-enabled=false") {
		t.Fatal("provider changed HTTPS-only exposure")
	}
	settings := smallKeycloakTestSettings()
	settings.SecretName = "trial-keycloak-state"
	material, err := BuildSmallKeycloakMaterial(settings, bytes.NewReader(bytes.Repeat([]byte{42}, 80)))
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range d.Spec.Template.Spec.Volumes {
		if volume.Name == "realm" {
			if volume.Secret == nil || len(volume.Secret.Items) != 1 || volume.Secret.SecretName != material.Name || material.Data[volume.Secret.Items[0].Key] == nil {
				t.Fatal("chart realm file absent from actual preparation")
			}
		}
	}
	db := kc["database"].(map[string]any)
	db["host"] = "external-postgres.example"
	db["credentialsSecretName"] = "external-kc-db"
	db["rootsSecretName"] = "external-pg-ca"
	values["services"].(map[string]any)["postgres"].(map[string]any)["provider"] = "external"
	raw, err = render()
	if err != nil {
		t.Fatalf("independent external database: %v\n%s", err, raw)
	}
	d, _ = read(raw)
	checkPoolRecovery(d.Spec.Template.Spec.Containers[0])
	for _, v := range d.Spec.Template.Spec.Containers[0].Env {
		if v.Name == "KC_DB_URL" && !strings.Contains(v.Value, "external-postgres.example") {
			t.Fatal("external database silently replaced")
		}
		if v.Name == "KCRAW_DB_PASSWORD" && v.ValueFrom.SecretKeyRef.Name != "external-kc-db" {
			t.Fatal("external database borrowed bundled password")
		}
	}
	db["rootsSecretName"] = ""
	if raw, err = render(); err == nil {
		t.Fatalf("missing external DB roots accepted: %s", raw)
	}
	db["rootsSecretName"] = "external-pg-ca"
	values["services"].(map[string]any)["identity"].(map[string]any)["provider"] = "external"
	raw, err = render()
	if err != nil {
		t.Fatalf("external identity changed existing chart: %v\n%s", err, raw)
	}
	if d, s := read(raw); d != nil || s != nil {
		t.Fatal("external provider unexpectedly installed Keycloak")
	}
}
