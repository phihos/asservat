package bootstrap

import (
	"context"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
)

// ADR-194 step 4: the derived promoted input passes the owner's own reader,
// pins the read-back key and projection, and refuses inconsistent parts.
func TestDerivePromotedOwner(t *testing.T) {
	for _, mode := range []string{"valid", "unprojected", "no-promotion", "already-native", "audit-mount", "other-signing-key", "no-worker-source", "foreign-capacity", "downloads", "downloads-other-source", "downloads-hub-namespace"} {
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
			case "downloads", "downloads-other-source", "downloads-hub-namespace":
				// ADR-204: the worker namespace's API, source and path template.
				revision := contracts.DownloadEnvironmentRevision{UID: runtimeID, Generation: 1, SHA256: strings.Repeat("c", 64)}
				x.Downloads = &promotedDownloads{API: contracts.OwnerNativeWorkerAPI{ClusterID: c.ClusterID, Namespace: contracts.WorkerObjectReference{Name: contracts.DownloadWorkerNamespaceName(c.InstallationID), UID: "20000000-0000-4000-8000-000000000001"}, Kubernetes: c.Kubernetes},
					Source: x.Sources.WorkerConfiguration, Template: contracts.DownloadEnvironmentPathTemplate{StoreID: runtimeID, StorageRegion: "r", AcquisitionClusterID: c.ClusterID, AcquisitionRegion: "r", ConnectorClusterID: c.ClusterID, ConnectorRegion: "r", HubClusterID: c.ClusterID, HubRegion: "r", WorkerConfiguration: revision, HubConfiguration: revision}}
				if mode == "downloads-other-source" {
					x.Downloads.Source = guarded("other")
				}
				if mode == "downloads-hub-namespace" {
					x.Downloads.API.Namespace = c.Namespace
				}
			}
			out, err := derivePromotedOwner(c, x, time.Now())
			if (err == nil) != (mode == "valid" || mode == "unprojected" || mode == "downloads") {
				t.Fatal(mode, err)
			}
			if err != nil {
				return
			}
			p := out.Public
			if p.WorkSigning.KeyID != signing.Name+"-v1" || p.ProviderRecipeSHA256 == "" || p.AuditStoreID != q.RootBacking.Capture.Policy.StoreID || p.RuntimeProjection != x.Projection ||
				out.Native.WorkerAPIs == nil || out.Native.RetentionTopologies == nil || p.WorkerConfiguration.Source != x.Sources.WorkerConfiguration.Source {
				t.Fatal("derived input", p)
			}
			if d := x.Downloads; d == nil && (len(out.Native.WorkerAPIs) != 0 || p.DownloadEnvironment.PathTemplate != nil) ||
				d != nil && (len(out.Native.WorkerAPIs) != 1 || !reflect.DeepEqual(out.Native.WorkerAPIs[0], d.API) || p.DownloadEnvironment.PathTemplate == nil || *p.DownloadEnvironment.PathTemplate != d.Template || len(p.DownloadEnvironment.Paths) != 0) {
				t.Fatal("download pins", out.Native.WorkerAPIs, p.DownloadEnvironment)
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
