package bootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func initialSeaweedInputFiles(t *testing.T, v contracts.InitialBootstrapInput, pgCA []byte, material map[string][]byte) *os.Root {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"bootstrap.json": raw, contracts.InitialBootstrapPostgresCAFile: pgCA}
	if material != nil {
		files[contracts.InitialBootstrapObjectStoreCAFile] = material["ca.crt"]
		files[contracts.InitialBootstrapObjectStorePlanFile] = material[contracts.SmallSeaweedPlanKey]
	}
	for name, data := range files {
		if data != nil {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestInitialSeaweedPublicSourceResolvesBeforeCanonicalIdentity(t *testing.T) {
	v, pgCA := smallBootstrapInput(t)
	plan := contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: v.BootstrapNamespace, Name: v.Name, Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64)}
	material, err := kube.BuildSmallSeaweedMaterial(plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v.AuditStore = contracts.InitialBootstrapAuditStoreInput{Endpoint: plan.Endpoint(), Region: "us-east-1", Bucket: "audit", RootsSource: contracts.InitialBootstrapBundledSeaweedRoots}
	if _, err := providerconfig.CompileInitialBootstrapInput(v, nil, nil, time.Now()); err == nil {
		t.Fatal("unresolved generated provider reached canonical compiler")
	}
	got, services, err := readInitialBootstrapDesiredAndServices(t.Context(), initialSeaweedInputFiles(t, v, pgCA, material))
	if err != nil || services.ObjectStore == nil || *services.ObjectStore != plan {
		t.Fatal("actual generated provider source not consumed", err)
	}
	v.AuditStore.RootsSource, v.AuditStore.RootsPEM = "", string(material["ca.crt"])
	explicit, external, err := readInitialBootstrapDesiredAndServices(t.Context(), initialSeaweedInputFiles(t, v, pgCA, nil))
	if err != nil || external.ObjectStore != nil || !reflect.DeepEqual(got, explicit) {
		t.Fatal("generated source changed canonical semantics", err)
	}
	v.AuditStore.RootsSource, v.AuditStore.RootsPEM = contracts.InitialBootstrapBundledSeaweedRoots, ""
	other, err := kube.BuildSmallSeaweedMaterial(plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	changed, _, err := readInitialBootstrapDesiredAndServices(t.Context(), initialSeaweedInputFiles(t, v, pgCA, other))
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(changed)
	if err != nil || bytes.Equal(a, b) {
		t.Fatal("actual provider CA excluded from original identity", err)
	}
	for _, mode := range []string{"missing", "unknown", "ambiguous", "namespace", "endpoint", "certificate"} {
		t.Run(mode, func(t *testing.T) {
			input := v
			data := map[string][]byte{}
			for key, value := range material {
				data[key] = value
			}
			switch mode {
			case "missing":
				data = nil
			case "unknown":
				input.AuditStore.RootsSource = "another-provider"
			case "ambiguous":
				input.AuditStore.RootsPEM = string(material["ca.crt"])
			case "namespace":
				p := plan
				p.Namespace = "another"
				data[contracts.SmallSeaweedPlanKey], _ = json.Marshal(p)
			case "endpoint":
				input.AuditStore.Endpoint = "https://another.example"
			case "certificate":
				data["ca.crt"] = []byte("not a certificate")
			}
			if _, _, err := readInitialBootstrapDesiredAndServices(t.Context(), initialSeaweedInputFiles(t, input, pgCA, data)); err == nil {
				t.Fatal("unavailable or mismatched source accepted")
			}
		})
	}
}
