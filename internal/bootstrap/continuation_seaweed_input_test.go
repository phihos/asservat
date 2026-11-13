package bootstrap

import (
	"context"
	"encoding/json"
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
