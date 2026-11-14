package kubernetes

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ownerWorkerCallerFixture struct {
	f          *ownerIdentityOperationFixture
	producer   *OwnerBootstrapSelectionProducer
	api        *ownerBootstrapAPIFixture
	selection  OwnerBootstrapAdvance
	resources  contracts.InitialRuntimeResourceSnapshot
	roles      contracts.ConfigurationRuntimeRoleSnapshot
	deployment apps.Deployment
	rolePath   string
}

// Caller holds the synthetic API fixture mutex.
func (f *ownerWorkerCallerFixture) store(t *testing.T, path string, object any) {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture object encoding")
	}
	f.f.api.objects[path] = value
}

func (f *ownerWorkerCallerFixture) roleObject(t *testing.T) core.Secret {
	t.Helper()
	raw, err := json.Marshal(f.roles.State)
	if err != nil {
		t.Fatal(err)
	}
	return core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: configurationWorkerRoleRootName(f.roles.State.Input.InstallationID), Namespace: f.roles.State.Input.Namespace.Name, UID: types.UID(f.roles.UID), ResourceVersion: f.roles.ResourceVersion},
		Type:       core.SecretTypeOpaque, Data: map[string][]byte{"state.json": raw}}
}
