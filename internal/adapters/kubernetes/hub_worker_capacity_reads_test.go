package kubernetes

import (
	"reflect"
	"strings"
	"testing"

	rbac "k8s.io/api/rbac/v1"
)

func TestInstalledWorkerCapacityReadProbeGraphIsClosed(t *testing.T) {
	w := &HubWorkerWorkload{Role: &rbac.Role{Rules: []rbac.PolicyRule{{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{"original"}, Verbs: []string{"get", "update"}}}}, ClusterRole: &rbac.ClusterRole{Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{"private"}, Verbs: []string{"get"}}}}}
	role, cluster := w.Role.DeepCopy(), w.ClusterRole.DeepCopy()
	installation := ownerID(1)
	augmentInstalledWorkerCapacityReads(w, installation)
	if !reflect.DeepEqual(role.Rules, w.Role.Rules[:1]) || !reflect.DeepEqual(cluster.Rules, w.ClusterRole.Rules[:1]) {
		t.Fatal("existing permission graph changed")
	}
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	want := []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{prefix + "-processing-source"}, Verbs: []string{"get", "update"}},
	}
	guards := []rbac.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{prefix + "-capacity-guard", prefix + "-processing-guard"}, Verbs: []string{"get"}}}
	if !reflect.DeepEqual(w.Role.Rules[1:], want) || !reflect.DeepEqual(w.ClusterRole.Rules[1:], guards) {
		t.Fatal("capacity read/probe permissions escaped fixed graph")
	}
}
