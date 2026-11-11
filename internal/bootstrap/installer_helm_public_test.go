package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Actual Helm output reaches the actual closed installer decoder and capacity
// compilers. All source identities/footprints are explicitly synthetic; this
// proves packaging compatibility, not native authority or backend capacity.
func TestHelmContextContinuationUsesActualInstallerDTO(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("Helm is required for the chart producer/consumer check")
	}
	raw, err := os.ReadFile("testdata/helm_context_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("invalid public test input")
	}
	var expected contracts.InstallerPublicSettings
	if json.Unmarshal(raw, &expected) != nil {
		t.Fatal("test input differs from actual installer DTO")
	}
	public["origin"], public["issuer"], public["clientID"] = "https://asservat.example", "https://id.example/realms/org", "console"
	public["clients"] = []map[string]string{{"id": "console", "kind": "human"}}
	public["eligibleGroups"] = []string{"stable-group-id"}
	values := map[string]any{"bootstrap": map[string]any{
		"administrators": []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}},
		"enabled":        true, "image": "registry.example/asservat@sha256:" + strings.Repeat("a", 64), "targetNamespace": "asservat-runtime",
		"secrets":      map[string]string{"producer": "operator-producer", "schema": "operator-schema", "retirement": "operator-retirement"},
		"postgres":     map[string]string{"host": "postgres.example", "rootsPEM": "PUBLIC-CA"},
		"auditStore":   map[string]string{"endpoint": "https://store.example", "region": "region-a", "bucket": "audit", "rootsPEM": "PUBLIC-CA"},
		"keyService":   map[string]string{"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"},
		"fleet":        map[string]any{"issuer": "https://id.example/realms/org", "clients": []string{"console"}, "subjects": []map[string]string{{"id": "installer", "kind": "human"}}},
		"continuation": map[string]any{"enabled": true, "workerProvider": map[string]string{"authMount": "worker-k8s", "authMountAccessor": "auth_kubernetes_1"}, "ownerProvider": map[string]string{"authMount": "owner-k8s", "authMountAccessor": "auth_kubernetes_2"}, "ownerIssuerRootsPEM": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n", "public": public},
	}}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "public-values.json")
	if os.WriteFile(file, encoded, 0600) != nil {
		t.Fatal("write public values")
	}
	ctx, end := context.WithTimeout(t.Context(), 30*time.Second)
	defer end()
	output, err := exec.CommandContext(ctx, helm, "template", "asservat", "../../charts/asservat", "--namespace", "trusted-bootstrap", "--kube-version", "1.37.0", "-f", file).CombinedOutput()
	if err != nil {
		t.Fatalf("actual chart render: %v\n%s", err, output)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var projection []byte
	var initial []byte
	for {
		var resource struct {
			Kind string
			Data map[string]string
		}
		if err := decoder.Decode(&resource); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if body := resource.Data["bootstrap.json"]; body != "" {
			initial = []byte(body)
		}
		if body := resource.Data[contracts.InstallerContinuationFile]; body != "" {
			if projection != nil {
				t.Fatal("duplicate continuation producer")
			}
			projection = []byte(body)
		}
	}
	initialInput, err := contracts.DecodeInitialBootstrapInput(bytes.NewReader(initial))
	if err != nil {
		t.Fatal("rendered initial bootstrap rejected by actual decoder", err)
	}
	if !reflect.DeepEqual(initialInput.Administrators, []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}}) {
		t.Fatal("chart dropped explicit existing guard administrator")
	}
	got, err := contracts.DecodeInstallerContinuation(bytes.NewReader(projection))
	if err != nil || got.Public == nil {
		t.Fatal("rendered continuation rejected by actual decoder", err)
	}
	p := got.Public
	if !reflect.DeepEqual(p.Capacity, expected.Capacity) || !reflect.DeepEqual(p.Federation, expected.Federation) || !reflect.DeepEqual(p.Promotion, expected.Promotion) || !reflect.DeepEqual(p.RetentionBaseline, expected.RetentionBaseline) || !reflect.DeepEqual(p.ProcessingOperators, expected.ProcessingOperators) {
		t.Fatal("chart changed or omitted a typed public context input")
	}
	d := capacityDerivedFixture()
	if _, err := buildCapacityQualification(*p.Capacity, d, sequentialIDs()); err != nil {
		t.Fatal("rendered capacity rejected by actual consumer", err)
	}
	if _, err := buildConnectorBacking(p.Federation.Connector, p.Capacity.Backup, d.Root, d.Installation, d.AccountVersion, d.Root, time.Now()); err != nil {
		t.Fatal("rendered connector backing rejected by actual consumer", err)
	}
}
