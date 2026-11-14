package kubernetes

import (
	"strings"
	"testing"

	core "k8s.io/api/core/v1"
)

func initialWorkloadPlan() InitialInstallerWorkloadPlan {
	return InitialInstallerWorkloadPlan{Namespace: "install", Name: "installer", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "providers", Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64), Witness: "witness", FleetSource: "fleet", WitnessGuard: "witness-guard", FleetGuard: "fleet-guard", WorkloadGuard: "workload-guard"}
}

func TestInitialWorkloadRejectsInvalidDerivedRBACNames(t *testing.T) {
	p := initialWorkloadPlan()
	p.WriterAccount = strings.Repeat("a", 252)
	if _, err := BuildInitialInstallerWorkload(p); err == nil {
		t.Fatal("accepted a plan whose derived Role name cannot be created")
	}
}

func TestInitialPodBindsEverySecurityRelevantSpecField(t *testing.T) {
	w, err := BuildInitialInstallerWorkload(initialWorkloadPlan())
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Pod.Spec.SchedulingGates) != 1 || w.Pod.Spec.RestartPolicy != core.RestartPolicyNever || *w.Pod.Spec.AutomountServiceAccountToken || *w.Pod.Spec.ActiveDeadlineSeconds != 120 {
		t.Fatal("installer could start or restart implicitly")
	}
	want := InstallationPodSpecDigest(w.Pod.Spec)
	scheduled := w.Pod.Spec.DeepCopy()
	scheduled.NodeName = "node-1"
	scheduled.SchedulingGates = nil
	if InstallationPodSpecDigest(*scheduled) != want {
		t.Fatal("normal scheduling changed identity")
	}
	for _, change := range []func(*core.PodSpec){
		func(s *core.PodSpec) { s.Containers[0].Image = "other:latest" },
		func(s *core.PodSpec) { s.Containers[0].Command = []string{"/bin/sh"} },
		func(s *core.PodSpec) { s.ServiceAccountName = "administrator" },
		func(s *core.PodSpec) { s.Volumes[0].Projected.Sources[1].Secret.Name = "other-credentials" },
		func(s *core.PodSpec) { s.HostPID = true },
		func(s *core.PodSpec) {
			s.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "debug", Image: "other:latest"}}}
		},
	} {
		s := w.Pod.Spec.DeepCopy()
		change(s)
		if InstallationPodSpecDigest(*s) == want {
			t.Fatal("security mutation escaped spec binding")
		}
	}
	for _, r := range w.Roles {
		for _, rule := range r.Rules {
			for _, res := range rule.Resources {
				if res == "secrets" || res == "*" || res == "serviceaccounts/token" || res == "pods/exec" {
					t.Fatal("installer can read/mint/inject credentials", r.Name, res)
				}
			}
		}
	}
}
