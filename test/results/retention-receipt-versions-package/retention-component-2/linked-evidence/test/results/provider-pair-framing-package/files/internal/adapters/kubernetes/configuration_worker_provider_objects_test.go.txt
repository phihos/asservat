package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type configurationMaterialFixture struct {
	reader       *InstalledWorkerProjectionReader
	manifest     contracts.ConfigurationRuntimeCredentialManifest
	mounted      map[string][]byte
	sql, storage *core.Secret
	reads        atomic.Int32
	blockStorage bool
}

// This tests only exact material observation over real TLS. All original role
// facts are synthetic; no successful setup/current guard/SQL authority is claimed.
func newConfigurationMaterialFixture(t *testing.T) *configurationMaterialFixture {
	t.Helper()
	installation := ownerID(15001)
	names := runtimeResourceNames(installation)
	in := contracts.HubWorkerDeployment{InstallationID: installation, ClusterID: ownerID(15002), Namespace: contracts.WorkerObjectReference{Name: "control", UID: ownerID(15003)}, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: ownerID(15004)}, OwnerSource: contracts.WorkerObjectReference{Name: names.OwnerSource, UID: ownerID(15005)},
		Activation:             &contracts.HubWorkerRuntimeActivation{Deployment: contracts.WorkerObjectReference{Name: names.Worker, UID: ownerID(15006)}, ServiceAccount: contracts.WorkerObjectReference{Name: names.Worker, UID: ownerID(15007)}},
		ProviderInputs:         &contracts.ConfigurationWorkerInputProvenance{ConfigurationRoot: contracts.WorkerObjectReference{Name: configurationWorkerRoleRootName(installation), UID: ownerID(15008)}, ConfigurationSetupID: ownerID(15009), SQLProjection: contracts.WorkerObjectReference{Name: configurationWorkerSQLProjectionName(installation), UID: ownerID(15010)}},
		ProviderAuthentication: &contracts.ConfigurationProviderAuthentication{AuditCredentials: contracts.WorkerObjectReference{Name: names.WorkerProviders, UID: ownerID(15011)}}}
	f := &configurationMaterialFixture{mounted: map[string][]byte{}}
	f.manifest = contracts.ConfigurationRuntimeCredentialManifest{Format: contracts.ConfigurationRuntimeCredentialManifestFormat, RootUID: in.ProviderInputs.ConfigurationRoot.UID, SetupID: in.ProviderInputs.ConfigurationSetupID, Input: contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: in.InstallationID, InitialClaimID: ownerID(15012), ClusterID: in.ClusterID, Namespace: in.Namespace, Deployment: in.Activation.Deployment, ServiceAccount: in.Activation.ServiceAccount, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		name := "synthetic-" + purpose
		f.manifest.Roles = append(f.manifest.Roles, contracts.ConfigurationRuntimeCredentialProof{Purpose: purpose, Receipt: contracts.PublicRuntimeRoleReceipt{RoleName: name}})
		f.mounted[[]string{"sql-fleet.json", "sql-configuration.json", "sql-audit.json"}[i]], _ = json.Marshal(contracts.OwnerSQLCredential{Username: name, Password: "synthetic-test-only-password"})
	}
	f.mounted[contracts.ConfigurationRuntimeRoleManifestFile], _ = json.Marshal(f.manifest)
	sqlData := map[string][]byte{}
	for key, b := range f.mounted {
		sqlData[key] = bytes.Clone(b)
	}
	f.sql = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: in.ProviderInputs.SQLProjection.Name, Namespace: in.Namespace.Name, UID: types.UID(in.ProviderInputs.SQLProjection.UID), ResourceVersion: "17", Annotations: map[string]string{"asservat.io/role-root-uid": f.manifest.RootUID, "asservat.io/role-setup-id": f.manifest.SetupID, "asservat.io/projection-id": ownerID(15013)}}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: sqlData}
	credential, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "synthetic-test-key", SecretAccessKey: "synthetic-test-secret"})
	f.mounted[contracts.ConfigurationProviderAuditCredentialFile] = bytes.Clone(credential)
	f.storage = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: in.ProviderAuthentication.AuditCredentials.Name, Namespace: in.Namespace.Name, UID: types.UID(in.ProviderAuthentication.AuditCredentials.UID), ResourceVersion: "18"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{contracts.ConfigurationProviderAuditCredentialFile: credential}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reads.Add(1)
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		base := "/api/v1/namespaces/" + in.Namespace.Name + "/secrets/"
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case base + f.sql.Name:
			_ = json.NewEncoder(w).Encode(f.sql)
		case base + f.storage.Name:
			if f.blockStorage {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(f.storage)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(server.Close)
	client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-observer", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, in.ClusterID, cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	f.reader = &InstalledWorkerProjectionReader{client: client, input: in}
	return f
}

func TestConfigurationMaterialReadsOnlyOriginalMountedObjects(t *testing.T) {
	f := newConfigurationMaterialFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.reader.configurationProviderProjection(ctx, f.manifest, f.mounted); err != nil {
		t.Fatal("exact bounded material failed", err)
	}
	if f.reads.Load() != 2 {
		t.Fatal("material read enumerated or retried objects")
	}
}

func TestConfigurationMaterialRejectsIdentityShapeAndStaleMounts(t *testing.T) {
	changes := map[string]func(*configurationMaterialFixture){
		"SQL UID":         func(f *configurationMaterialFixture) { f.sql.UID = types.UID(ownerID(15020)) },
		"SQL mutable":     func(f *configurationMaterialFixture) { f.sql.Immutable = ptr.To(false) },
		"SQL extra key":   func(f *configurationMaterialFixture) { f.sql.Data["other-role.json"] = []byte("forbidden") },
		"SQL missing key": func(f *configurationMaterialFixture) { delete(f.sql.Data, "sql-audit.json") },
		"SQL stale mounted credential": func(f *configurationMaterialFixture) {
			f.mounted["sql-fleet.json"] = []byte(`{"username":"changed","password":"changed"}`)
		},
		"SQL original root":       func(f *configurationMaterialFixture) { f.sql.Annotations["asservat.io/role-root-uid"] = ownerID(15020) },
		"SQL malformed operation": func(f *configurationMaterialFixture) { f.sql.Annotations["asservat.io/projection-id"] = "" },
		"SQL returned manifest":   func(f *configurationMaterialFixture) { f.manifest.SetupID = ownerID(15020) },
		"SQL role purpose": func(f *configurationMaterialFixture) {
			f.manifest.Roles[0].Purpose = "configuration-audit"
			b, _ := json.Marshal(f.manifest)
			f.sql.Data[contracts.ConfigurationRuntimeRoleManifestFile] = b
			f.mounted[contracts.ConfigurationRuntimeRoleManifestFile] = bytes.Clone(b)
		},
		"storage UID": func(f *configurationMaterialFixture) { f.storage.UID = types.UID(ownerID(15020)) },
		"storage extra unmounted key": func(f *configurationMaterialFixture) {
			f.storage.Data["foreign-credentials.json"] = []byte("forbidden")
		},
		"storage stale rotation": func(f *configurationMaterialFixture) {
			f.storage.Data[contracts.ConfigurationProviderAuditCredentialFile] = []byte(`{"accessKeyID":"new","secretAccessKey":"new","sessionToken":""}`)
		},
		"storage malformed": func(f *configurationMaterialFixture) {
			b := []byte(`{"accessKeyID":"","secretAccessKey":"new","sessionToken":""}`)
			f.storage.Data[contracts.ConfigurationProviderAuditCredentialFile] = b
			f.mounted[contracts.ConfigurationProviderAuditCredentialFile] = bytes.Clone(b)
		},
		"mounted foreign key": func(f *configurationMaterialFixture) { f.mounted["audit-wrap.token"] = []byte("forbidden") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := newConfigurationMaterialFixture(t)
			change(f)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.reader.configurationProviderProjection(ctx, f.manifest, f.mounted); err == nil {
				t.Fatal("changed material accepted")
			}
			if f.reads.Load() > 2 {
				t.Fatal("denial retried or enumerated material")
			}
		})
	}
}

func TestConfigurationMaterialRetainsOriginalDeadlineAfterBlockingRead(t *testing.T) {
	f := newConfigurationMaterialFixture(t)
	f.blockStorage = true
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := f.reader.configurationProviderProjection(ctx, f.manifest, f.mounted)
	if err == nil || ctx.Err() == nil || f.reads.Load() != 2 {
		t.Fatal("blocking material read renewed original deadline or retried", err)
	}
	if strings.Contains(err.Error(), "synthetic-test-secret") {
		t.Fatal("error disclosed storage credentials")
	}
}
