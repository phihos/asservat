package kubernetes

import (
	"slices"
	"testing"
)

// The executor's connector resolves preview targets in its own cluster
// (ADR-179): namespace, workload, the Pod list by selector and the
// Pod → ReplicaSet → Deployment chain. Native 59 answered denied without the
// ReplicaSet read outside the connector namespace. ADR-230 adds the Event
// LIST of a probe policy's poll.
func TestRegionalExecutorCanReadTargetChain(t *testing.T) {
	cluster, _, _ := regionalExecutorRBAC("region")
	can := func(group, resource, verb string) bool {
		for _, r := range cluster {
			if len(r.ResourceNames) == 0 && slices.Contains(r.APIGroups, group) && slices.Contains(r.Resources, resource) && slices.Contains(r.Verbs, verb) {
				return true
			}
		}
		return false
	}
	for _, need := range [][3]string{{"", "namespaces", "get"}, {"", "pods", "get"}, {"", "pods", "list"}, {"apps", "deployments", "get"}, {"apps", "statefulsets", "get"}, {"apps", "replicasets", "get"}, {"", "events", "list"}} {
		if !can(need[0], need[1], need[2]) {
			t.Errorf("connector cannot %s %s/%s cluster-wide", need[2], need[0], need[1])
		}
	}
	for _, r := range cluster {
		for _, v := range r.Verbs {
			if (slices.Contains(r.Resources, "replicasets") || slices.Contains(r.Resources, "pods") || slices.Contains(r.Resources, "events")) && v != "get" && v != "list" {
				t.Fatalf("target reads must stay read-only: %v", r)
			}
		}
	}
}
