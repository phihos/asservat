package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Actual loopback TLS exercises only the native object readers. Its objects and
// receipts are synthetic; this fixture confers no current guard/SQL authority.
type ownerIdentityObjectFixture struct {
	extra      func(http.ResponseWriter, *http.Request) bool
	apiConfig  *rest.Config
	plan       cfg.OwnerWorkloadAdministration
	reader     *InstalledOwnerIdentityReader
	state      contracts.InitialRuntimeResourceState
	manifest   contracts.OwnerIdentityCredentialManifest
	mounted    map[string][]byte
	journal    *core.Secret
	providers  *core.Secret
	config     *core.ConfigMap
	deployment *apps.Deployment
	account    *core.ServiceAccount
}

func newOwnerIdentityObjectFixture(t *testing.T) *ownerIdentityObjectFixture {
	t.Helper()
	s, v, in, a := ownerIdentityActivationFixture(t)
	x := &ownerIdentityObjectFixture{state: v, manifest: contracts.OwnerIdentityCredentialManifest{Format: contracts.OwnerIdentityCredentialManifestFormat, Input: a.Input, RootUID: a.RoleRoot.UID, SetupID: a.RoleSetupID}, mounted: map[string][]byte{}}
	for _, name := range []string{contracts.OwnerIdentityRoleManifestFile, "sql-owner-runtime.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token"} {
		x.mounted[name] = []byte("synthetic-" + name)
	}
	x.mounted[contracts.OwnerIdentityRoleManifestFile], _ = json.Marshal(x.manifest)
	p := v.OwnerIdentity
	encoded, _ := json.Marshal(in)
	x.config = &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: p.Receipt.Configuration.Name, Namespace: in.Namespace.Name, UID: types.UID(p.Receipt.Configuration.UID), ResourceVersion: p.Receipt.ConfigurationResourceVersion, Annotations: ownerIdentityReaderAnnotations(a, p, p.Configuration)}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(encoded)}}
	x.providers = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: p.Receipt.Credentials.Name, Namespace: in.Namespace.Name, UID: types.UID(p.Receipt.Credentials.UID), ResourceVersion: p.Receipt.CredentialsResourceVersion, Annotations: ownerIdentityReaderAnnotations(a, p, p.Credentials)}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{}}
	for k, b := range x.mounted {
		x.providers.Data[k] = append([]byte(nil), b...)
	}
	digest, e := ownerIdentityPublicDigest(in, x.manifest)
	if e != nil {
		t.Fatal(e)
	}
	p.PublicDigest = digest
	obj, e := s.object(v, 10)
	if e != nil {
		t.Fatal(e)
	}
	x.deployment = obj.object.(*apps.Deployment)
	x.state.OwnerLaunch.InertDigest, _ = ownerIdentitySpecDigest(*x.deployment)
	x.deployment.Spec.Replicas = ptr.To(int32(1))
	x.deployment.UID = types.UID(a.Input.Deployment.UID)
	x.deployment.ResourceVersion = "2"
	x.deployment.Generation = 2
	x.deployment.Annotations = map[string]string{initialRuntimeResourceMarker: v.Objects[10].OperationID, ownerIdentityLaunchMarker: v.OwnerLaunch.OperationID, "deployment.kubernetes.io/revision": "1"}
	x.state.OwnerLaunch.RunningDigest, _ = ownerIdentitySpecDigest(*x.deployment)
	obj, e = s.object(v, 0)
	if e != nil {
		t.Fatal(e)
	}
	x.account = obj.object.(*core.ServiceAccount)
	x.account.UID = types.UID(a.Input.ServiceAccount.UID)
	x.account.ResourceVersion = "1"
	x.account.Generation = 1
	x.account.Annotations = map[string]string{initialRuntimeResourceMarker: v.Objects[0].OperationID}
	x.journal = &core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: a.Input.Resources.Name, Namespace: in.Namespace.Name, UID: types.UID(a.Input.Resources.UID), ResourceVersion: "8"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{}}
	x.writeJournal(t)
	inventory, e := s.inventory(v)
	if e != nil {
		t.Fatal(e)
	}
	x.plan = inventory.BridgeAdministration.Owner
	prefix := "/api/v1/namespaces/" + in.Namespace.Name
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if x.extra != nil && x.extra(w, r) {
			return
		}
		if r.Method != http.MethodGet {
			t.Error("reader attempted mutation")
			http.Error(w, "read only", 403)
			return
		}
		switch r.URL.Path {
		case prefix + "/secrets/" + x.journal.Name:
			permissionReply(w, x.journal)
		case prefix + "/secrets/" + x.providers.Name:
			permissionReply(w, x.providers)
		case prefix + "/configmaps/" + x.config.Name:
			permissionReply(w, x.config)
		case prefix + "/serviceaccounts/" + x.account.Name:
			permissionReply(w, x.account)
		case "/apis/apps/v1/namespaces/" + in.Namespace.Name + "/deployments/" + x.deployment.Name:
			permissionReply(w, x.deployment)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	x.apiConfig = &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	client, e := NewPermissionClient(x.apiConfig, in.ClusterID, cfg.NamespaceRef{Name: in.Namespace.Name, UID: in.Namespace.UID}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	x.reader = &InstalledOwnerIdentityReader{client: client, input: in, activation: a, podUID: ownerID(3300)}
	return x
}

func (x *ownerIdentityObjectFixture) writeJournal(t *testing.T) {
	t.Helper()
	raw, e := json.Marshal(x.state)
	if e != nil {
		t.Fatal(e)
	}
	x.journal.Data["state.json"] = raw
}

func TestOwnerIdentityNativeReadersRequireOriginalMountedBundle(t *testing.T) {
	for _, mode := range []string{"valid", "missing-child-marker", "swapped-child-marker", "missing-projection-receipt", "missing-launch-receipt", "journal-replacement", "role-root-substitution", "mutable-provider", "provider-replacement", "different-mounted-credential", "extra-mounted-credential", "config-substitution", "late", "new-image", "scaled", "launch-substitution", "account-replacement"} {
		t.Run(mode, func(t *testing.T) {
			x := newOwnerIdentityObjectFixture(t)
			switch mode {
			case "missing-child-marker":
				delete(x.providers.Annotations, "asservat.io/owner-identity-object")
			case "swapped-child-marker":
				x.config.Annotations["asservat.io/owner-identity-object"] = x.state.OwnerIdentity.Credentials.OperationID
			case "missing-projection-receipt":
				x.state.OwnerIdentity.Receipt = nil
				x.writeJournal(t)
			case "missing-launch-receipt":
				x.state.OwnerLaunch.Receipt = nil
				x.writeJournal(t)
			case "journal-replacement":
				x.journal.UID = types.UID(ownerID(3400))
			case "role-root-substitution":
				x.state.OwnerIdentity.RoleRoot.UID = ownerID(3400)
				x.writeJournal(t)
			case "mutable-provider":
				x.providers.Immutable = ptr.To(false)
			case "provider-replacement":
				x.providers.UID = types.UID(ownerID(3400))
			case "different-mounted-credential":
				x.mounted["sql-owner-runtime.json"] = []byte("other-synthetic")
			case "extra-mounted-credential":
				x.mounted["sql-administrator.json"] = []byte("synthetic")
			case "config-substitution":
				x.config.Data["deployment.json"] = strings.ReplaceAll(x.config.Data["deployment.json"], x.reader.input.ClusterID, ownerID(3400))
			case "new-image":
				x.deployment.Spec.Template.Spec.Containers[0].Image = "other"
			case "scaled":
				*x.deployment.Spec.Replicas = 2
			case "launch-substitution":
				x.deployment.Annotations[ownerIdentityLaunchMarker] = ownerID(3400)
			case "account-replacement":
				x.account.UID = types.UID(ownerID(3400))
			}
			until := time.Now().Add(5 * time.Second)
			if mode == "late" {
				until = time.Now().Add(-time.Second)
			}
			ctx, end := context.WithDeadline(context.Background(), until)
			defer end()
			state, e := x.reader.journal(ctx)
			if e == nil {
				e = x.reader.projections(ctx, state, x.manifest, x.mounted)
			}
			if e == nil {
				e = x.reader.deployment(ctx, state)
			}
			if mode == "valid" && e != nil {
				t.Fatal("original mounted objects denied", e)
			}
			if mode != "valid" {
				var failure *OwnerIdentityReadFailure
				if !errors.As(e, &failure) {
					t.Fatal("missing closed object diagnostic", e)
				}
				expected := map[string]OwnerIdentityReadCheck{
					"missing-child-marker": ownerReadCredentialsMetadata, "swapped-child-marker": ownerReadConfigurationMetadata,
					"missing-projection-receipt": ownerReadJournalState, "missing-launch-receipt": ownerReadLaunchReceipt,
					"journal-replacement": ownerReadJournalMetadata, "role-root-substitution": ownerReadJournalState,
					"mutable-provider": ownerReadCredentialsMetadata, "provider-replacement": ownerReadCredentialsMetadata,
					"different-mounted-credential": ownerReadCredentialsContent, "extra-mounted-credential": ownerReadCredentialsMetadata,
					"config-substitution": ownerReadConfigurationContent, "late": ownerReadJournalRead,
					"new-image": ownerReadDeploymentRunningDigest, "scaled": ownerReadDeploymentMetadata,
					"launch-substitution": ownerReadDeploymentMetadata, "account-replacement": ownerReadAccountContent,
				}[mode]
				if failure.Check() != expected {
					t.Fatalf("wrong native object diagnostic: mode=%s error=%v", mode, e)
				}
			}
			if mode != "valid" && e == nil {
				t.Fatal("changed/pending installation accepted")
			}
		})
	}
}
