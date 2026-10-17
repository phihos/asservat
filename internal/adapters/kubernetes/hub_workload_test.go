package kubernetes

import (
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
)

func workerWorkloadPlan() HubWorkerWorkloadPlan {
	return HubWorkerWorkloadPlan{Namespace: "private", Name: "reconciler", ServiceAccount: "reconciler", Configuration: "inputs", Credentials: "providers", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), FleetSource: "fleet", OwnerSource: "owners", FleetGuard: "fleet-guard", OwnerGuard: "owner-guard", LeaderLease: "schedule"}
}

func TestHubWorkerWorkloadBoundaries(t *testing.T) {
	p := workerWorkloadPlan()
	w, err := BuildHubWorkerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	pod := w.Deployment.Spec.Template.Spec
	c := pod.Containers[0]
	if *w.Deployment.Spec.Replicas != 0 || *pod.AutomountServiceAccountToken || *pod.EnableServiceLinks || *w.Account.AutomountServiceAccountToken || pod.ServiceAccountName != p.ServiceAccount {
		t.Fatal("unprotected startup or automatic token mount")
	}
	if pod.HostNetwork || pod.HostPID || pod.HostIPC || len(pod.InitContainers) != 0 || len(pod.Containers) != 1 || !*pod.SecurityContext.RunAsNonRoot || *pod.SecurityContext.RunAsUser != 65532 || pod.SecurityContext.SeccompProfile.Type != core.SeccompProfileTypeRuntimeDefault || !*c.SecurityContext.ReadOnlyRootFilesystem || *c.SecurityContext.AllowPrivilegeEscalation || !reflect.DeepEqual(c.SecurityContext.Capabilities.Drop, []core.Capability{"ALL"}) {
		t.Fatal("restricted process boundary")
	}
	if !reflect.DeepEqual(c.Command, []string{"/asservat", "hub-worker"}) || len(c.Env) != 0 || len(c.EnvFrom) != 0 || len(c.Ports) != 0 || c.Resources.Limits.Cpu().IsZero() || c.Resources.Limits.Memory().IsZero() {
		t.Fatal("unbounded or public process")
	}
	if len(pod.Volumes) != 1 || pod.Volumes[0].Projected == nil || len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != contracts.HubWorkerDeploymentRoot || !c.VolumeMounts[0].ReadOnly || c.VolumeMounts[0].SubPath != "" {
		t.Fatal("credential projection boundary")
	}
	projection := pod.Volumes[0].Projected
	if *projection.DefaultMode != 0440 || len(projection.Sources) != 5 {
		t.Fatal("projection permissions")
	}
	if cm := projection.Sources[0].ConfigMap; cm == nil || cm.Name != p.Configuration || *cm.Optional || !reflect.DeepEqual(cm.Items, []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}}) {
		t.Fatal("configuration projection")
	}
	secret := projection.Sources[1].Secret
	if secret == nil || secret.Name != p.Credentials || *secret.Optional {
		t.Fatal("credential selection")
	}
	got := []string{}
	for _, file := range secret.Items {
		if file.Key != file.Path {
			t.Fatal("renamed secret")
		}
		got = append(got, file.Key)
	}
	if !reflect.DeepEqual(got, []string{"sql-fleet.json", "sql-configuration.json", "sql-audit.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token"}) {
		t.Fatal("unexpected credentials", got)
	}
	for i, path := range []string{"kube-observer.token", "kube-probe.token", "kube-leader.token"} {
		v := projection.Sources[i+2].ServiceAccountToken
		if v == nil || v.Path != path || v.Audience != "" || *v.ExpirationSeconds != 600 {
			t.Fatal("token projection")
		}
	}
	expected := []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.FleetSource, p.OwnerSource}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{p.LeaderLease}, Verbs: []string{"get", "update"}},
	}
	if !reflect.DeepEqual(w.Role.Rules, expected) {
		t.Fatal("unexpected namespace privilege")
	}
	expected = []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{p.FleetGuard, p.OwnerGuard}, Verbs: []string{"get"}},
	}
	if !reflect.DeepEqual(w.ClusterRole.Rules, expected) {
		t.Fatal("unexpected cluster privilege")
	}
	want := []rbac.Subject{{Kind: "ServiceAccount", Name: p.ServiceAccount, Namespace: p.Namespace}}
	if !reflect.DeepEqual(w.Binding.Subjects, want) || !reflect.DeepEqual(w.ClusterBinding.Subjects, want) || w.Binding.RoleRef.Name != w.Role.Name || w.ClusterBinding.RoleRef.Name != w.ClusterRole.Name {
		t.Fatal("privilege binding")
	}
	w.Binding.Subjects[0].Name = "mutated"
	w.Deployment.Spec.Template.Labels["asservat.io/workload"] = "mutated"
	if !reflect.DeepEqual(w.ClusterBinding.Subjects, want) || w.Deployment.Spec.Selector.MatchLabels["asservat.io/workload"] != p.Name {
		t.Fatal("object alias")
	}
}

func TestHubWorkerWorkloadInvalidPlans(t *testing.T) {
	for _, change := range []func(*HubWorkerWorkloadPlan){
		func(p *HubWorkerWorkloadPlan) { p.Namespace = "" }, func(p *HubWorkerWorkloadPlan) { p.ServiceAccount = "*" }, func(p *HubWorkerWorkloadPlan) { p.Credentials = "../secret" }, func(p *HubWorkerWorkloadPlan) { p.Name = strings.Repeat("a", 64) },
		func(p *HubWorkerWorkloadPlan) { p.OwnerSource = p.FleetSource }, func(p *HubWorkerWorkloadPlan) { p.OwnerGuard = p.FleetGuard }, func(p *HubWorkerWorkloadPlan) { p.Configuration = p.FleetSource }, func(p *HubWorkerWorkloadPlan) { p.Configuration = p.OwnerSource },
		func(p *HubWorkerWorkloadPlan) { p.Image = "image:latest" }, func(p *HubWorkerWorkloadPlan) { p.Image = "https://image@sha256:" + strings.Repeat("a", 64) }, func(p *HubWorkerWorkloadPlan) { p.Image = "image@sha256:" + strings.Repeat("A", 64) }, func(p *HubWorkerWorkloadPlan) { p.Image = "image@sha256:" + strings.Repeat("z", 64) },
	} {
		p := workerWorkloadPlan()
		change(&p)
		if _, err := BuildHubWorkerWorkload(p); err == nil {
			t.Fatal("invalid plan accepted", p)
		}
	}
	a, b := workerWorkloadPlan(), workerWorkloadPlan()
	a.Namespace = "a-b"
	a.Name = "c"
	b.Namespace = "a"
	b.Name = "b-c"
	wa, _ := BuildHubWorkerWorkload(a)
	wb, _ := BuildHubWorkerWorkload(b)
	if wa.ClusterRole.Name == wb.ClusterRole.Name {
		t.Fatal("cluster role name collision")
	}
}
