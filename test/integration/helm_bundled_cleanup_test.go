package integration

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
)

func TestHelmBundledPublicCleanupPreservesGuardedRuntimeForOwnedHarness(t *testing.T) {
	desired := contracts.InitialBootstrap{Name: "install", BootstrapNamespace: "bootstrap", TargetNamespace: "runtime"}
	api := fake.NewSimpleClientset(
		&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "bootstrap", UID: "original-bootstrap"}},
		&core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "runtime", UID: "original-runtime"}},
		&admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: "original-runtime-permission-guard", UID: "original-policy"}},
		&admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: "original-runtime-permission-guard", UID: "original-binding"}},
		&core.PersistentVolumeClaim{ObjectMeta: meta.ObjectMeta{Namespace: "bootstrap", Name: "original-postgres-data", UID: "original-pvc"}},
	)
	helmBootstrapCleanup(t, api, desired, "original-bootstrap", true)
	// The main journey separately requires the original five positive exits,
	// hook absence and retained source checks. Cleanup must not remove guards
	// or start namespace/PVC deletion beneath the still-running installation.
	if actions := api.Actions(); len(actions) != 0 {
		t.Fatal("full runtime used bootstrap-only API cleanup", actions)
	}
	for _, object := range []struct{ resource, namespace, name string }{
		{"namespaces", "", "runtime"},
		{"namespaces", "", "bootstrap"},
		{"validatingadmissionpolicies", "", "original-runtime-permission-guard"},
		{"validatingadmissionpolicybindings", "", "original-runtime-permission-guard"},
		{"persistentvolumeclaims", "bootstrap", "original-postgres-data"},
	} {
		group, version := "", "v1"
		if object.resource == "validatingadmissionpolicies" || object.resource == "validatingadmissionpolicybindings" {
			group, version = "admissionregistration.k8s.io", "v1"
		}
		if _, err := api.Tracker().Get(schema.GroupVersionResource{Group: group, Version: version, Resource: object.resource}, object.namespace, object.name); err != nil {
			t.Fatal("runtime source removed before owned environment teardown", err)
		}
	}
}
