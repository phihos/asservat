package kubernetes

import (
	"reflect"
	"slices"
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
		{APIGroups: []string{"asservat.io"}, Resources: []string{"evidencestoragepools", "evidencebudgetpolicies"}, Verbs: []string{"get", "list", "create"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{prefix + "-processing-source"}, Verbs: []string{"get", "update"}},
	}
	guards := []rbac.PolicyRule{{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{prefix + "-capacity-guard", prefix + "-processing-guard"}, Verbs: []string{"get"}}}
	if !reflect.DeepEqual(w.Role.Rules[1:], want) || !reflect.DeepEqual(w.ClusterRole.Rules[1:], guards) {
		t.Fatal("capacity read/probe permissions escaped fixed graph")
	}
}

func TestInstalledWorkerOriginalRoleReceiptsCoverCapacityGraph(t *testing.T) {
	installed, state := installedWorkerResourceFixture(t)
	legacy, old := initialRuntimeResourceFixture(t)
	for _, index := range []int{6, 8} {
		actual, err := installed.object(state, index)
		if err != nil || preparationDigest(actual.object) != state.Objects[index].TemplateDigest {
			t.Fatal("original installed Role claim does not bind capacity graph", err)
		}
		prior, err := legacy.object(old, index)
		if err != nil || preparationDigest(prior.object) == preparationDigest(actual.object) {
			t.Fatal("legacy Role claim adopted installed capacity graph", err)
		}
		var rules []rbac.PolicyRule
		if index == 6 {
			rules = actual.object.(*rbac.Role).Rules
		} else {
			rules = actual.object.(*rbac.ClusterRole).Rules
		}
		found := false
		for _, rule := range rules {
			if index == 6 && slices.Contains(rule.Resources, "evidencestoragepools") || index == 8 && slices.Contains(rule.ResourceNames, "asservat-"+strings.ReplaceAll(installed.initial.InstallationID, "-", "")+"-capacity-guard") {
				found = true
			}
		}
		if !found {
			t.Fatal("installed builder omitted capacity observer/probe grant")
		}
	}
}
