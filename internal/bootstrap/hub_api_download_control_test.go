package bootstrap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// The hub-api completes the hub-local download workers' control from the
// Helm-rendered profile, the store Secret's UID and the accepted owner pool,
// writes it as the control ConfigMap's only key (once per content) and the
// worker trust catalog accepts the same document.
func TestHubAPIDownloadControlPublish(t *testing.T) {
	ctx := context.Background()
	hubAPIFiles(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, HubAPIDownloadKeyServiceCAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubAPICAFixture[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	h := hubAPIConfigFixture()
	c := contracts.OwnerDeployment{InstallationID: runtimeID, ClusterID: runtimeID, AuditStore: contracts.OwnerAuditStore{Roots: hubAPICAFixture},
		Public: &contracts.OwnerPublicDeployment{ArtifactKeyID: artifactKeyID(runtimeID)},
		Native: &contracts.OwnerNativeDeployment{WorkerAPIs: []contracts.OwnerNativeWorkerAPI{{ClusterID: runtimeID, Namespace: contracts.WorkerObjectReference{Name: "asservat-downloads", UID: runtimeID}}}}}
	if _, err = buildHubAPIDownloadControl(ctx, files, h, c, "not-a-store", time.Now()); err == nil {
		t.Fatal("control without the evidence store ID")
	}
	empty, _ := os.OpenRoot(t.TempDir())
	defer empty.Close()
	if _, err = buildHubAPIDownloadControl(ctx, empty, h, c, runtimeID, time.Now()); err == nil {
		t.Fatal("control without the key service CA")
	}
	o, err := buildHubAPIDownloadControl(ctx, files, h, c, runtimeID, time.Now())
	if err != nil || o == nil || o.namespace != "asservat-downloads" || o.store.Bucket != "asservat-evidence" || o.keys.Endpoint != "https://asservat-key-service.hub.svc:9447" {
		t.Fatal("control values", o, err)
	}

	profile, _ := json.Marshal(contracts.WorkerConfiguration{Format: contracts.WorkerConfigurationFormat, Revision: 1, Namespace: "asservat-downloads", ServiceAccount: "asservat-download-worker", PriorityClass: "asservat-download-worker",
		ControlConfig: "asservat-download-worker-control", Image: "registry.invalid/asservat", ImagePullSecrets: []string{}, CPUMillis: 500, MemoryBytes: 1 << 28, MaxRuntimeSeconds: 600, StoreCredentials: "asservat-s3-download-read"})
	api := fake.NewClientset(
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "asservat-worker-profile", Namespace: "asservat-downloads"}, Data: map[string]string{"worker-profile.json": string(profile)}},
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "asservat-download-worker-control", Namespace: "asservat-downloads"}},
		&core.Secret{ObjectMeta: meta.ObjectMeta{Name: "asservat-s3-download-read", Namespace: "asservat-downloads", UID: types.UID(runtimeID)}})
	pool := value.OwnerPool{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, Namespace: "hub", NamespaceUID: runtimeID, Service: "asservat-hub-api-owner", ServiceUID: runtimeID, Deployment: "asservat-hub-api", DeploymentUID: runtimeID, ServiceAccount: "asservat-hub-api", AccountUID: runtimeID, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
	raw, err := o.publish(ctx, api, runtimeID, runtimeID, pool, hubAPICAFixture, hubAPICAFixture)
	if err != nil {
		t.Fatal("publish", err)
	}
	written, _ := api.CoreV1().ConfigMaps("asservat-downloads").Get(ctx, "asservat-download-worker-control", meta.GetOptions{})
	if len(written.Data) != 1 || written.Data["worker.json"] != string(raw) {
		t.Fatal("control ConfigMap content", written.Data)
	}
	control, err := mtls.ParseWorkerControl(raw)
	if err != nil || control.Native() == nil || control.Native().Settings().StoreID != runtimeID || control.Native().Settings().StoreCredentialSecretUID != runtimeID || control.Address != "asservat-hub-api-owner.hub.svc:9443" {
		t.Fatal("control document", err)
	}
	trust, err := mtls.NewWorkerTrustCatalog(runtimeID, [][]byte{raw})
	if err != nil || !trust.ForInstallation(runtimeID) {
		t.Fatal("trust catalog refused the written control", err)
	}
	updates := 0
	for _, a := range api.Actions() {
		if a.GetVerb() == "update" {
			updates++
		}
	}
	if again, err := o.publish(ctx, api, runtimeID, runtimeID, pool, hubAPICAFixture, hubAPICAFixture); err != nil || string(again) != string(raw) {
		t.Fatal("republish", err)
	}
	for _, a := range api.Actions() {
		if a.GetVerb() == "update" {
			updates--
		}
	}
	if updates != 0 {
		t.Fatal("unchanged control rewritten")
	}
	if err = api.CoreV1().Secrets("asservat-downloads").Delete(ctx, "asservat-s3-download-read", meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = o.publish(ctx, api, runtimeID, runtimeID, pool, hubAPICAFixture, hubAPICAFixture); err == nil {
		t.Fatal("control without the store Secret")
	}
}
