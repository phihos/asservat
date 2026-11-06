package integration

import (
	"context"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/kubernetes/fake"
)

// The live fixture parses the actual generated guard expressions.
func TestInstalledLiveAdministratorMatchesGeneratedGuards(t *testing.T) {
	control := cfg.NamespaceRef{Name: "hub", UID: "10000000-0000-4000-8000-000000000001"}
	delivery, _, err := kube.DownloadEnvironmentAdmission(cfg.ConfigMapAdministration{Name: "delivery-guard", SourceName: "delivery", ControlNamespace: control, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "runner"}}})
	if err != nil {
		t.Fatal(err)
	}
	api := fake.NewSimpleClientset(delivery)
	user, groups, err := installedLiveAdministrator(context.Background(), api, "delivery-guard", "delivery-guard")
	if err != nil || user != "runner" || len(groups) != 0 {
		t.Fatal(user, groups, err)
	}
}
