package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func TestInitialOpenBaoSourceResolvesBeforeCanonicalIdentity(t *testing.T) {
	v, pgCA := smallBootstrapInput(t)
	apiRoots, err := providerconfig.TrustRootsPEM([]byte(v.Kubernetes.RootsPEM), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: v.BootstrapNamespace, Name: v.Name, Image: contracts.SmallOpenBaoImage,
		Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: v.Kubernetes.Endpoint, Roots: apiRoots}, SetupAccount: v.RunnerAccount}
	material, err := kube.BuildSmallOpenBaoMaterial(plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v.KeyService = contracts.InitialBootstrapKeyServiceInput{Endpoint: plan.Endpoint(), AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: "audit", RootsSource: contracts.InitialBootstrapBundledOpenBaoRoots}
	v.Providers = contracts.SmallOpenBaoInitialProviders()
	files := func(input contracts.InitialBootstrapInput, data map[string][]byte) *os.Root {
		r := smallBootstrapFiles(t, input, pgCA)
		for path, key := range map[string]string{contracts.InitialBootstrapKeyServicePlanFile: contracts.SmallOpenBaoPlanKey, contracts.InitialBootstrapKeyServiceCAFile: "ca.crt", contracts.InitialBootstrapKeyServiceBackendFile: contracts.SmallOpenBaoBackendKey} {
			if data != nil {
				if err := os.WriteFile(filepath.Join(r.Name(), path), data[key], 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return r
	}
	got, selected, err := readInitialBootstrapDesiredAndServices(t.Context(), files(v, material))
	if err != nil || selected.KeyService == nil || !reflect.DeepEqual(*selected.KeyService, plan) {
		t.Fatal("actual public source not resolved", err)
	}
	explicit := v
	explicit.KeyService.RootsSource, explicit.KeyService.RootsPEM = "", string(material["ca.crt"])
	want, external, err := readInitialBootstrapDesiredAndServices(t.Context(), files(explicit, nil))
	if err != nil || external.KeyService != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("generated public trust changed canonical identity", err)
	}
	for _, mode := range []string{"missing", "unknown", "ambiguous", "namespace", "api", "api-ca", "endpoint", "mount", "backend"} {
		t.Run(mode, func(t *testing.T) {
			input := v
			data := map[string][]byte{}
			for k, b := range material {
				data[k] = b
			}
			switch mode {
			case "missing":
				data = nil
			case "unknown":
				input.KeyService.RootsSource = "unknown"
			case "ambiguous":
				input.KeyService.RootsPEM = string(material["ca.crt"])
			case "namespace":
				p := plan
				p.Namespace = "another"
				data[contracts.SmallOpenBaoPlanKey], _ = json.Marshal(p)
			case "api":
				input.Kubernetes.Endpoint = "https://another.invalid"
			case "api-ca":
				input.Kubernetes.RootsPEM = string(material["ca.crt"])
			case "endpoint":
				input.KeyService.Endpoint = "https://another.invalid"
			case "mount":
				input.KeyService.AuditMount = "another"
			case "backend":
				data[contracts.SmallOpenBaoBackendKey] = []byte("unknown")
			}
			if _, _, err := readInitialBootstrapDesiredAndServices(t.Context(), files(input, data)); err == nil {
				t.Fatal("foreign or unavailable bundled source accepted")
			}
		})
	}
}
