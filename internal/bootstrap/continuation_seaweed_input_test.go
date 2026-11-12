package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

func TestContinuationSeaweedSourceBindsOriginalStore(t *testing.T) {
	v, pgCA := smallBootstrapInput(t)
	plan := contracts.SmallSeaweedPlan{Format: contracts.SmallSeaweedFormat, Namespace: v.BootstrapNamespace, Name: v.Name, Image: "chrislusf/seaweedfs@sha256:" + strings.Repeat("a", 64)}
	material, err := kube.BuildSmallSeaweedMaterial(plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots, err := providerconfig.TrustRootsPEM(material["ca.crt"], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var original contracts.InitialPreparer
	original.Plan.BootstrapNamespace.Name = plan.Namespace
	original.Plan.RootName = plan.Name + "-preparation"
	original.Services = &contracts.InitialPreparationServices{AuditStore: contracts.OwnerAuditStore{Endpoint: plan.Endpoint(), Roots: roots, Region: "us-east-1", Bucket: "original-audit"}}
	input := func() contracts.InstallerContinuation {
		return contracts.InstallerContinuation{Namespace: plan.Namespace, ObjectStoreSource: contracts.InitialBootstrapBundledSeaweedRoots,
			Public: &contracts.InstallerPublicSettings{Federation: &contracts.InstallerFederationSettings{EvidenceStore: &contracts.InstallerEvidenceStore{Endpoint: plan.Endpoint(), Region: "us-east-1", Bucket: "original-audit"}}}}
	}
	files := initialSeaweedInputFiles(t, v, pgCA, material)
	i := input()
	selected, resolved, err := resolveInstallerContinuationObjectStore(t.Context(), files, &i)
	if err != nil || selected == nil || *selected != plan || !continuationObjectStoreMatchesOriginal(selected, resolved, i, original) {
		t.Fatal("original generated store not resolved", err)
	}
	explicit := input()
	explicit.ObjectStoreSource = ""
	explicit.Public.Federation.EvidenceStore.RootsPEM = string(material["ca.crt"])
	a, _ := json.Marshal(i)
	b, _ := json.Marshal(explicit)
	if string(a) != string(b) {
		t.Fatal("generated and explicit provider inputs differ")
	}
	for _, name := range []string{"unknown", "namespace", "endpoint", "ambiguous", "missing", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			in := input()
			ctx := t.Context()
			f := files
			switch name {
			case "unknown":
				in.ObjectStoreSource = "unknown"
			case "namespace":
				in.Namespace = "another"
			case "endpoint":
				in.Public.Federation.EvidenceStore.Endpoint = "https://another.invalid"
			case "ambiguous":
				in.Public.Federation.EvidenceStore.RootsPEM = string(material["ca.crt"])
			case "missing":
				f = initialSeaweedInputFiles(t, v, pgCA, nil)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, _, err := resolveInstallerContinuationObjectStore(ctx, f, &in); err == nil {
				t.Fatal("unavailable or ambiguous source accepted")
			}
		})
	}
	for _, name := range []string{"root-name", "namespace", "endpoint", "ca", "evidence-bucket", "evidence-region", "missing-services"} {
		t.Run("original-"+name, func(t *testing.T) {
			in := input()
			d := original
			services := *original.Services
			d.Services = &services
			switch name {
			case "missing-services":
				d.Services = nil
			case "root-name":
				d.Plan.RootName = "another-preparation"
			case "namespace":
				d.Plan.BootstrapNamespace.Name = "another"
			case "endpoint":
				d.Services.AuditStore.Endpoint = "https://another.invalid"
			case "ca":
				d.Services.AuditStore.Roots = [][]byte{[]byte("another")}
			case "evidence-bucket":
				in.Public.Federation.EvidenceStore.Bucket = "another"
			case "evidence-region":
				in.Public.Federation.EvidenceStore.Region = "another"
			}
			if continuationObjectStoreMatchesOriginal(&plan, roots, in, d) {
				t.Fatal("different original store accepted")
			}
		})
	}
	observation := input()
	observation.Public = nil
	if p, r, err := resolveInstallerContinuationObjectStore(t.Context(), files, &observation); err != nil || !continuationObjectStoreMatchesOriginal(p, r, observation, original) || observation.Public != nil {
		t.Fatal("observation-only selection fabricated executor configuration", err)
	}
	unchanged := explicit
	before, _ := json.Marshal(unchanged)
	if p, r, err := resolveInstallerContinuationObjectStore(t.Context(), files, &unchanged); err != nil || p != nil || r != nil {
		t.Fatal("external selection consumed bundled provider", err)
	}
	after, _ := json.Marshal(unchanged)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("external selection changed")
	}
}

func TestHelmContinuationBundledStoreCoordinates(t *testing.T) {
	raw, err := os.ReadFile("testdata/helm_context_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("public reference")
	}
	public["origin"], public["issuer"], public["clientID"] = "https://console.example", "https://identity.example/realms/asservat", "asservat-console"
	public["clients"] = []map[string]string{{"id": "asservat-console", "kind": "human"}}
	public["eligibleGroups"] = []string{"stable-group-id"}
	federation := public["federation"].(map[string]any)
	federation["evidenceStore"] = map[string]any{}
	b := smallServicesHelmBootstrap()
	_, _, ownerRoots := serverCertificate(t)
	b["continuation"] = map[string]any{"enabled": true, "public": public,
		"workerProvider":      map[string]string{"authMount": "worker", "authMountAccessor": "worker-accessor"},
		"ownerProvider":       map[string]string{"authMount": "owner", "authMountAccessor": "owner-accessor"},
		"ownerIssuerRootsPEM": ownerRoots}
	values := map[string]any{"bootstrap": b, "services": map[string]any{"objectStore": map[string]any{"provider": "seaweedfs"}}}
	got := renderReferenceContinuation(t, values)
	e := got.Public.Federation.EvidenceStore
	if got.ObjectStoreSource != contracts.InitialBootstrapBundledSeaweedRoots || e == nil || e.Endpoint != "https://trial-objectstore.trusted-bootstrap.svc:8333" || e.RootsPEM != "" || e.Bucket != "audit" || e.Region != "test" {
		t.Fatal("actual chart failed to select generated public store", e)
	}
	// External configuration must still supply every previously required field;
	// the selected bundled mode may not weaken the external schema.
	for _, mode := range []string{"external-empty", "bundled-other-bucket"} {
		t.Run(mode, func(t *testing.T) {
			var in map[string]any
			encoded, _ := json.Marshal(values)
			_ = json.Unmarshal(encoded, &in)
			if mode == "external-empty" {
				in["services"].(map[string]any)["objectStore"].(map[string]any)["provider"] = "external"
			} else {
				in["bootstrap"].(map[string]any)["continuation"].(map[string]any)["public"].(map[string]any)["federation"].(map[string]any)["evidenceStore"].(map[string]any)["bucket"] = "another"
			}
			encoded, _ = json.Marshal(in)
			file := filepath.Join(t.TempDir(), "values.json")
			if err := os.WriteFile(file, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			if err := exec.CommandContext(ctx, "helm", "template", "asservat", "../../charts/asservat", "--namespace", "trusted-bootstrap", "--kube-version", "1.37.0", "-f", file).Run(); err == nil {
				t.Fatal("unsupported store input accepted")
			}
		})
	}
}
