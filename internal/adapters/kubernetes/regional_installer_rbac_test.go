package kubernetes

import (
	"os"
	"slices"
	"strings"
	"testing"

	rbac "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// The chart's cluster-installer creates the regional Roles/ClusterRoles, so
// Kubernetes' escalation check requires it to hold every permission it grants
// (it holds neither escalate nor bind). Native tests install regions as an
// administrator and never exercise this account.
func TestChartClusterInstallerHoldsRegionalGrants(t *testing.T) {
	raw, err := os.ReadFile("../../../charts/asservat/templates/cluster-installer.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var installer rbac.ClusterRole
	for _, doc := range strings.Split(string(raw), "\n---\n") {
		if !strings.Contains(doc, "\nkind: ClusterRole\n") {
			continue
		}
		var plain []string
		for _, line := range strings.Split(doc, "\n") {
			if !strings.Contains(line, "{{") {
				plain = append(plain, line)
			}
		}
		if err := yaml.Unmarshal([]byte(strings.Join(plain, "\n")), &installer); err != nil {
			t.Fatal(err)
		}
	}
	if len(installer.Rules) == 0 {
		t.Fatal("cluster-installer ClusterRole not found")
	}
	ns := "region"
	clusterRole, role := regionalRBAC(ns)
	cluster, connector, capacity := regionalExecutorRBAC(ns)
	granted := slices.Concat(clusterRole.Rules, role.Rules, cluster, connector, capacity.Rules, regionalCapacityRBAC(ns),
		// ensureCapacityProbe's probe ClusterRole and token Role.
		[]rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get", "update"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{CapacityProbeAccount}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{CapacityProbeAccount}, Verbs: []string{"get"}}})
	holds := func(group, resource, verb, name string) bool {
		for _, r := range installer.Rules {
			if slices.Contains(r.APIGroups, group) && slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) &&
				(len(r.ResourceNames) == 0 || slices.Contains(r.ResourceNames, name)) {
				return true
			}
		}
		return false
	}
	for _, g := range granted {
		names := g.ResourceNames
		if len(names) == 0 {
			names = []string{""}
		}
		for _, group := range g.APIGroups {
			for _, resource := range g.Resources {
				for _, verb := range g.Verbs {
					for _, name := range names {
						if !holds(group, resource, verb, name) {
							t.Errorf("cluster-installer cannot grant %s %s/%s %s", verb, group, resource, name)
						}
					}
				}
			}
		}
	}
}
