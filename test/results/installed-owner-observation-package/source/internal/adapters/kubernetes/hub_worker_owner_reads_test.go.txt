package kubernetes

import (
	"reflect"
	"testing"

	rbac "k8s.io/api/rbac/v1"
)

func TestInstalledWorkerOwnerReadGraphIsClosed(t *testing.T) {
	w := &HubWorkerWorkload{Role: &rbac.Role{Rules: []rbac.PolicyRule{{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{"original"}, Verbs: []string{"get", "update"}}}}}
	original := w.Role.DeepCopy()
	installation := ownerID(1)
	augmentInstalledWorkerOwnerReads(w, installation)
	if !reflect.DeepEqual(original.Rules, w.Role.Rules[:1]) {
		t.Fatal("existing permissions changed")
	}
	name := runtimeResourceNames(installation).Owner
	want := []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"services", "serviceaccounts"}, ResourceNames: []string{name}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
	}
	if !reflect.DeepEqual(w.Role.Rules[1:], want) {
		t.Fatal("local metadata permissions changed")
	}
}
