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
	"k8s.io/apimachinery/pkg/util/yaml"
)

// The actual chart and closed decoder must preserve empty selected-provider
// inputs until the original provider resolves its own distinct issuer roots.
func TestHelmContinuationBundledOpenBaoDefaultsReachActualResolver(t *testing.T) {
	for _, explicitEmpty := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "empty"}[explicitEmpty], func(t *testing.T) {
			f := newContinuationBaoFixture(t, "")
			values := continuationBaoHelmValues(t, true)
			c := values["bootstrap"].(map[string]any)["continuation"].(map[string]any)
			federation := c["public"].(map[string]any)["federation"].(map[string]any)
			delete(federation, "connectorPKIMount")
			delete(federation, "connectorIssuerRootsPEM")
			if explicitEmpty {
				federation["connectorPKIMount"], federation["connectorIssuerRootsPEM"] = "", ""
			}
			got, output, err := renderContinuationBaoValues(t, values)
			if err != nil {
				t.Fatalf("selected provider render/decode: %v\n%s", err, output)
			}
			if got.KeyServiceSource != contracts.InitialBootstrapBundledOpenBaoRoots || got.WorkerProvider.AuthMount != "" || got.OwnerProvider.AuthMountAccessor != "" || got.OwnerIssuerRootsPEM != "" || got.Public.Federation.ConnectorPKIMount != "" || got.Public.Federation.ConnectorIssuerRootsPEM != "" {
				t.Fatal("chart substituted selected provider facts")
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			provider, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &got, f.original(t), f.base.config, f.open)
			if err != nil {
				t.Fatal("rendered defaults rejected by actual resolver", err)
			}
			defer provider.Close()
			if got.KeyServiceSource != "" || got.WorkerProvider.AuthMount != contracts.SmallOpenBaoConfigurationAuthMount || got.OwnerProvider.AuthMount != contracts.SmallOpenBaoOwnerAuthMount || got.OwnerIssuerRootsPEM != f.issuer || got.Public.Federation.ConnectorPKIMount != contracts.SmallOpenBaoConnectorPKIMount || got.Public.Federation.ConnectorIssuerRootsPEM != f.connectorIssuer || f.issuer == f.connectorIssuer {
				t.Fatal("actual provider identity or distinct issuer roots lost")
			}
		})
	}
}

func TestHelmContinuationOpenBaoPreservesExternalRequirements(t *testing.T) {
	for _, mode := range []string{"missing-provider", "missing-owner-roots", "missing-connector", "empty-connector", "valid-external", "conflicting-bundled"} {
		t.Run(mode, func(t *testing.T) {
			selected := mode == "conflicting-bundled"
			values := continuationBaoHelmValues(t, selected)
			c := values["bootstrap"].(map[string]any)["continuation"].(map[string]any)
			c["workerProvider"], c["ownerProvider"] = map[string]string{"authMount": "worker-k8s", "authMountAccessor": "auth_worker"}, map[string]string{"authMount": "owner-k8s", "authMountAccessor": "auth_owner"}
			c["ownerIssuerRootsPEM"] = "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"
			federation := c["public"].(map[string]any)["federation"].(map[string]any)
			switch mode {
			case "missing-provider":
				delete(c, "workerProvider")
			case "missing-owner-roots":
				delete(c, "ownerIssuerRootsPEM")
			case "missing-connector":
				delete(federation, "connectorPKIMount")
				delete(federation, "connectorIssuerRootsPEM")
			case "empty-connector":
				federation["connectorPKIMount"], federation["connectorIssuerRootsPEM"] = "", ""
			}
			got, output, err := renderContinuationBaoValues(t, values)
			if mode != "valid-external" && !selected {
				if err == nil {
					t.Fatal("external requirement silently derived")
				}
				return
			}
			if err != nil {
				t.Fatalf("render/decode: %v\n%s", err, output)
			}
			if got.WorkerProvider.AuthMount != "worker-k8s" || got.OwnerProvider.AuthMount != "owner-k8s" || got.OwnerIssuerRootsPEM != c["ownerIssuerRootsPEM"] {
				t.Fatal("supplied provider settings changed")
			}
			if selected {
				f := newContinuationBaoFixture(t, "")
				ctx, end := context.WithTimeout(t.Context(), time.Minute)
				defer end()
				if p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &got, f.original(t), f.base.config, f.open); err == nil || p != nil || f.opens != 0 {
					t.Fatal("conflicting supplied mount reached login or was accepted")
				}
			} else if got.KeyServiceSource != "" {
				t.Fatal("external provider selected a bundled source")
			}
		})
	}
}

func continuationBaoHelmValues(t *testing.T, selected bool) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/helm_context_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if err = json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	public["origin"], public["issuer"], public["clientID"] = "https://console.example", "https://identity.example/realms/asservat", "asservat-console"
	public["clients"] = []map[string]string{{"id": "asservat-console", "kind": "human"}}
	public["eligibleGroups"] = []string{"stable-group-id"}
	b := smallServicesHelmBootstrap()
	b["continuation"] = map[string]any{"enabled": true, "public": public}
	provider := "external"
	if selected {
		provider = "openbao"
	}
	return map[string]any{"bootstrap": b, "services": map[string]any{"keyService": map[string]any{"provider": provider}}}
}
func renderContinuationBaoValues(t *testing.T, values map[string]any) (contracts.InstallerContinuation, []byte, error) {
	t.Helper()
	var got contracts.InstallerContinuation
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Fatal("Helm required for actual producer regression", err)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "values.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, end := context.WithTimeout(t.Context(), 30*time.Second)
	defer end()
	output, err := exec.CommandContext(ctx, helm, "template", "trial", "../../charts/asservat", "--namespace", "bootstrap", "--kube-version", "1.37.0", "-f", path).CombinedOutput()
	if err != nil {
		return got, output, err
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	for {
		var object struct{ Data map[string]string }
		err = decoder.Decode(&object)
		if err == io.EOF {
			break
		}
		if err != nil {
			return got, output, err
		}
		if body := object.Data[contracts.InstallerContinuationFile]; body != "" {
			got, err = contracts.DecodeInstallerContinuation(strings.NewReader(body))
			return got, output, err
		}
	}
	t.Fatal("missing actual continuation projection")
	return got, output, nil
}
