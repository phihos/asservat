package kubernetes

import (
	"slices"
	"testing"
)

func TestRegionalNodeInputReadRuleIsOneExistingSecret(t *testing.T) {
	rule := regionalNodeInputReadRule()
	if !slices.Equal(rule.APIGroups, []string{""}) || !slices.Equal(rule.Resources, []string{"secrets"}) || !slices.Equal(rule.ResourceNames, []string{RegionalNodes}) || !slices.Equal(rule.Verbs, []string{"get"}) || len(rule.NonResourceURLs) != 0 {
		t.Fatal("listener input metadata permission widened", rule)
	}
	// Kubernetes RBAC authorizes a resource request only when every attribute
	// matches a rule. The added rule supplies no other name/list/watch/update.
	for _, tc := range []struct {
		name, verb string
		allowed    bool
	}{{RegionalNodes, "get", true}, {"another-secret", "get", false}, {RegionalNodes, "list", false}, {RegionalNodes, "watch", false}, {RegionalNodes, "update", false}} {
		allowed := slices.Contains(rule.ResourceNames, tc.name) && slices.Contains(rule.Verbs, tc.verb)
		if allowed != tc.allowed {
			t.Fatal("unexpected listener Secret permission", tc)
		}
	}
}
