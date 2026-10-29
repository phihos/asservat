package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// Exercise the actual namespace/Deployment builder, including the explicit
// profile argument: a global native-paced focus cannot promote another target.
func TestNativePacingTargetResourceProfileIsExplicit(t *testing.T) {
	for _, c := range []struct {
		name, focus    string
		paced          bool
		request, limit int64
	}{
		{"ordinary", "", false, 5, 100},
		{"other-target-in-paced-focus", "native-paced", false, 5, 100},
		{"measured-target", "native-paced", true, 200, 200},
		{"approved-recording", "approved-recording", false, 5, 100},
		{"policy-recording", "policy-recording", false, 5, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", c.focus)
			api := fake.NewClientset()
			w := createRegionalWorkload(t, t.Context(), api, "synthetic-image", "synthetic-app", c.paced)
			deployed, err := api.AppsV1().Deployments(w.ns.Name).Get(t.Context(), w.app.Name, meta.GetOptions{})
			if err != nil || len(deployed.Spec.Template.Spec.Containers) != 1 || deployed.Spec.Replicas == nil || *deployed.Spec.Replicas != 1 {
				t.Fatal("actual target shape", err)
			}
			if err := nativePacingRequireTargetProfile(&core.Pod{Spec: deployed.Spec.Template.Spec}); (err == nil) != c.paced {
				t.Fatal("actual built target passed the wrong declared-profile gate", err)
			}
			r := deployed.Spec.Template.Spec.Containers[0].Resources
			if r.Requests.Cpu().MilliValue() != c.request || r.Limits.Cpu().MilliValue() != c.limit || r.Requests.Memory().Value() != 16<<20 || r.Limits.Memory().Value() != 64<<20 {
				t.Fatal("declared profile changed another resource", r)
			}
		})
	}
}

// Real observer composition through a fake Kubernetes API and a bounded local
// command double. No Docker operation, container or cgroup is created/read.
func TestNativePacingCPUObserverMatchesDeclaredPodProfile(t *testing.T) {
	id := strings.Repeat("1", 64)
	for _, c := range []struct {
		name    string
		paced   bool
		quota   string
		changed string
		ok      bool
	}{
		{"default100", false, "10000", "", true},
		{"paced200", true, "20000", "", true},
		{"wrong-effective-quota", true, "10000", "", false},
		{"changed-limit", true, "20000", "limit", false},
		{"changed-request", true, "20000", "request", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			expected := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "exact", Namespace: "synthetic", UID: types.UID("exact-pod")}, Spec: core.PodSpec{NodeName: "owned-node", Containers: []core.Container{{Name: "app", Resources: regionalWorkloadResources(c.paced)}}}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{Name: "app", ContainerID: "containerd://" + id}}}}
			current := expected.DeepCopy()
			switch c.changed {
			case "limit":
				current.Spec.Containers[0].Resources.Limits[core.ResourceCPU] = resource.MustParse("100m")
			case "request":
				current.Spec.Containers[0].Resources.Requests[core.ResourceCPU] = resource.MustParse("5m")
			}
			if err := nativePacingRequireTargetProfile(current); (err == nil) != (c.paced && c.changed == "") {
				t.Fatal("changed/100m actual declaration passed native-paced gate", err)
			}
			api := fake.NewClientset(current)
			dir := t.TempDir()
			calls := filepath.Join(dir, "calls")
			script := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$3" >> "$ASSERVAT_CPU_PROFILE_CALLS"
case "$3" in
crictl) printf '%%s\n' '{"info":{"pid":1234},"status":{"id":"%s","state":"CONTAINER_RUNNING"}}' ;;
cat) printf '%%s\n' "$ASSERVAT_CPU_PROFILE_QUOTA 100000" 'usage_usec 100' 'user_usec 60' 'system_usec 40' 'nr_periods 9' 'nr_throttled 3' 'throttled_usec 700' ;;
*) exit 2 ;;
esac
`, id)
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			t.Setenv("ASSERVAT_CPU_PROFILE_CALLS", calls)
			t.Setenv("ASSERVAT_CPU_PROFILE_QUOTA", c.quota)
			got, err := nativeTrafficTargetCPU(t.Context(), api, expected)
			if c.ok {
				if err != nil || got.ContainerID != expected.Status.ContainerStatuses[0].ContainerID || got.Quota*1000 != got.Period*uint64(expected.Spec.Containers[0].Resources.Limits.Cpu().MilliValue()) || got.Counters["usage_usec"] != 100 || got.DeclaredRequestMilliCPU != expected.Spec.Containers[0].Resources.Requests.Cpu().MilliValue() || got.DeclaredLimitMilliCPU != expected.Spec.Containers[0].Resources.Limits.Cpu().MilliValue() {
					t.Fatal("actual observer lost declared profile", got, err)
				}
			} else if err == nil {
				t.Fatal("changed/unavailable profile accepted")
			}
			observed, _ := os.ReadFile(calls)
			if c.changed != "" && len(observed) != 0 {
				t.Fatal("changed declared target reached node command")
			}
			if c.ok && string(observed) != "crictl\ncat\n" {
				t.Fatal("observer did not use existing two bounded commands", string(observed))
			}
		})
	}
}
