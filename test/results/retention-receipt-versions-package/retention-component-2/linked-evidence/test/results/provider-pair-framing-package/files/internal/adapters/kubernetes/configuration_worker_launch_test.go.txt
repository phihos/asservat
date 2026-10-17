package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestConfigurationLegacyLaunchRejectsRecognizedProviderInputsBeforeClaim(t *testing.T) {
	f := newConfigurationLaunchFixture(t)
	in := f.root.input
	input := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: in.InstallationID, ClusterID: in.ClusterID, Namespace: in.Namespace, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource,
		ProviderAuthentication: &contracts.ConfigurationProviderAuthentication{Format: contracts.ConfigurationProviderAuthenticationFormat}, ProviderInputs: &contracts.ConfigurationWorkerInputProvenance{OperationID: ownerID(16201)}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	f.path.mu.Lock()
	previous := f.path.extraHandler
	f.path.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/"+in.Namespace.Name+"/configmaps/"+f.configuration.Name {
			permissionReply(w, core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: f.configuration.Name, Namespace: in.Namespace.Name, UID: types.UID(f.configuration.UID), ResourceVersion: "1"}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(raw)}})
			return true
		}
		return previous(w, r)
	}
	f.path.mu.Unlock()
	before := f.path.secretWrites.Load()
	if err := f.launch(); err == nil {
		t.Fatal("legacy launch silently selected provider profile")
	}
	if f.writes.Load() != 0 || f.path.secretWrites.Load() != before {
		t.Fatal("invalid profile consumed claim or wrote deployment")
	}
}

func TestConfigurationProviderLaunchCannotForgeOpaqueSetupCheck(t *testing.T) {
	p := &configurationWorkerLaunchCheck{}
	if p.current(context.Background()) || p.before(context.Background(), nil, contracts.ConfigurationRuntimeRoleSnapshot{}, apps.Deployment{}) == nil {
		t.Fatal("empty setup acquired launch authority")
	}
}
