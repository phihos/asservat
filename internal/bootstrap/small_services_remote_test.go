package bootstrap

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ADR-330: with the bundled object store every joined cluster gets its own
// regional capabilities, scoped to its cluster ID; mode=hub generates no
// hub-cluster regional principal.
func TestSecretsHookScopesJoinedClusterCapabilities(t *testing.T) {
	const installation, hub, root, remote = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002", "10000000-0000-4000-8000-000000000003", "50000000-0000-4000-8000-000000000001"
	api := fake.NewClientset()
	store := secretStore{api: api.CoreV1().Secrets("hub"), namespace: "hub"}
	admin, err := providerconfig.GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: "admin", ScopeID: "10000000-0000-4000-8000-000000000009"})
	if err != nil {
		t.Fatal(err)
	}
	p := contracts.SecretsPlan{Name: "asservat", Mode: "hub", ObjectStore: &contracts.SmallSeaweedPlan{Namespace: "hub", Name: "asservat"}, RemoteClusters: []contracts.SecretsRemoteCluster{{Name: "eu", ClusterID: remote}}}
	ids := installationIDs{"installationID": installation, "clusterID": hub, "permissionRootID": root}
	if err = store.objectStore(t.Context(), p, ids, admin); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"asservat-s3-regional-write-eu", "asservat-s3-regional-history-eu"} {
		if _, err = api.CoreV1().Secrets("hub").Get(t.Context(), name, meta.GetOptions{}); err != nil {
			t.Fatal(name, err)
		}
	}
	if _, err = api.CoreV1().Secrets("hub").Get(t.Context(), "asservat-s3-regional-write", meta.GetOptions{}); err == nil {
		t.Fatal("mode=hub generated the hub cluster's regional principal")
	}
	iam, err := api.CoreV1().Secrets("hub").Get(t.Context(), p.ObjectStore.IAMSecretName(), meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	config := string(iam.Data[providerconfig.SeaweedConfigKey]) + string(iam.Data[SeaweedBucketPoliciesKey])
	if !strings.Contains(config, "asservat-regional-write-"+remote) || !strings.Contains(config, root+"/"+remote) || strings.Contains(config, "asservat-regional-write-"+hub) {
		t.Fatal("regional principals not scoped to the joined cluster")
	}
	p.RemoteClusters[0].ClusterID = hub
	if err = store.objectStore(t.Context(), p, ids, admin); err == nil {
		t.Fatal("the hub cluster accepted as a joined cluster")
	}
}
