package bootstrap

import (
	"context"
	"encoding/pem"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
)

// ADR-194 step 4: the derived promoted input passes the owner's own reader,
// pins the read-back key and projection, and refuses inconsistent parts.
func TestDerivePromotedOwner(t *testing.T) {
	for _, mode := range []string{"valid", "unprojected", "no-promotion", "already-native", "audit-mount", "other-signing-key", "no-worker-source", "foreign-capacity"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := ownerProviderInputFixture(t)
			d := capacityDerivedFixture()
			d.Root, d.Installation = c.PermissionRootID, c.InstallationID
			q, err := buildCapacityQualification(capacityProfileFixture(), d, sequentialIDs())
			if err != nil {
				t.Fatal(err)
			}
			ref := func(name string) contracts.WorkerObjectReference {
				return contracts.WorkerObjectReference{Name: name, UID: runtimeID}
			}
			guarded := func(name string) contracts.OwnerPublicGuardedSource {
				return contracts.OwnerPublicGuardedSource{Source: ref(name), Guard: contracts.OwnerDeploymentGuard{Name: name + "-guard", PolicyUID: runtimeID, PolicyGeneration: 1, BindingUID: runtimeID, BindingResourceVersion: "1"}}
			}
			promotion := contracts.InstallerOwnerPromotion{BrowserAudience: "asservat-api", ProviderRootsPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Kubernetes.Roots[0]})), TransitMount: "public-transit", WorkerPKIMount: "worker-pki", Version: "v1"}
			_, signing, _ := promotedKeyNames(c.InstallationID, runtimeID, promotion)
			signing.Version, signing.PublicKey = 1, make([]byte, 32)
			x := promotedOwnerParts{Settings: contracts.InstallerPublicSettings{Origin: "https://asservat.example.test", Promotion: &promotion},
				Sources: kube.PublicSources{BrowserRootID: runtimeID, BrowserSettings: ref("browser-settings"), IdentitySettings: ref("identity-settings"),
					ClusterCatalog: guarded("catalog"), WorkerConfiguration: guarded("worker"), DownloadEnvironment: guarded("environment")},
				Qualification: q, ConnectorRoots: c.Kubernetes.Roots, IssuerEpoch: runtimeID, Signing: signing, WorkerRoots: c.Kubernetes.Roots,
				Projection: contracts.WorkerObjectReference{Name: contracts.PublicRuntimeProjectionName(c.InstallationID), UID: runtimeID}}
			// The continuation derives before the owner projection attaches
			// the observation activation; the launched input carries it.
			activation := c.Observation.Activation
			switch mode {
			case "unprojected":
				c.Observation.Activation = nil
			case "no-promotion":
				x.Settings.Promotion = nil
			case "already-native":
				c.Native = &contracts.OwnerNativeDeployment{}
			case "audit-mount":
				promotion.TransitMount = c.KeyService.AuditMount
				x.Signing.Mount = promotion.TransitMount
			case "other-signing-key":
				x.Signing.Name = "other"
			case "no-worker-source":
				x.Sources.WorkerConfiguration = contracts.OwnerPublicGuardedSource{}
			case "foreign-capacity":
				x.Qualification.RootBacking.Capture.Policy.RootID = "10000000-0000-4000-8000-0000000000ff"
			}
			out, err := derivePromotedOwner(c, x, time.Now())
			if (err == nil) != (mode == "valid" || mode == "unprojected") {
				t.Fatal(mode, err)
			}
			if err != nil {
				return
			}
			p := out.Public
			if p.WorkSigning.KeyID != signing.Name+"-v1" || p.ProviderRecipeSHA256 == "" || p.AuditStoreID != q.RootBacking.Capture.Policy.StoreID || p.RuntimeProjection != x.Projection ||
				out.Native.WorkerAPIs == nil || len(out.Native.WorkerAPIs) != 0 || out.Native.RetentionTopologies == nil || p.WorkerConfiguration.Source != x.Sources.WorkerConfiguration.Source {
				t.Fatal("derived input", p)
			}
			if mode == "unprojected" {
				if validateOwnerDeployment(out) == nil {
					t.Fatal("unprojected input passed the launched owner's check")
				}
				out.Observation.Activation = activation
			}
			writeOwnerJSON(t, dir, "deployment.json", out)
			got, err := readOwnerInputs(context.Background(), in.files)
			if err != nil {
				t.Fatal("owner reader refused the derived input", err)
			}
			got.closeHTTP()
		})
	}
}
