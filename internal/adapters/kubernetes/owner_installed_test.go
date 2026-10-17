package kubernetes

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func installedOwnerPlan() OwnerWorkloadPlan {
	id := ownerID(1)
	n := runtimeResourceNames(id)
	return OwnerWorkloadPlan{InstallationID: id, Namespace: "asservat-hub", Name: n.Owner, ServiceAccount: n.Owner, Configuration: n.OwnerInputs, Credentials: n.OwnerProviders, WorkloadGuard: n.WorkloadGuard, Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64)}
}

func TestInstalledOwnerIdentityFirstWorkload(t *testing.T) {
	p := installedOwnerPlan()
	legacy, err := BuildOwnerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	w, err := BuildInstalledOwnerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	if w.Deployment.Spec.Replicas == nil || *w.Deployment.Spec.Replicas != 0 {
		t.Fatal("a template cannot authorize its own launch")
	}
	pod := w.Deployment.Spec.Template.Spec
	if len(pod.Containers) != 1 || len(pod.InitContainers) != 0 || len(pod.Volumes) != 3 || len(pod.Containers[0].VolumeMounts) != 3 {
		t.Fatal("unexpected installed process or projection")
	}
	if pod.HostPID || pod.HostNetwork || pod.HostIPC || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Fatal("installed layout widened Pod access")
	}
	if !reflect.DeepEqual(pod.SecurityContext, legacy.Deployment.Spec.Template.Spec.SecurityContext) || !reflect.DeepEqual(pod.Containers[0].SecurityContext, legacy.Deployment.Spec.Template.Spec.Containers[0].SecurityContext) {
		t.Fatal("installed layout changed Restricted security context")
	}
	identity := pod.Volumes[0].Projected.Sources
	if len(identity) != 5 || identity[0].ConfigMap == nil || identity[1].Secret == nil || identity[0].ConfigMap.Optional == nil || *identity[0].ConfigMap.Optional || identity[1].Secret.Optional == nil || *identity[1].Secret.Optional {
		t.Fatal("identity projections must remain mandatory")
	}
	if !reflect.DeepEqual(identity[0].ConfigMap.Items, []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}}) {
		t.Fatal("identity startup depends on worker routing configuration")
	}
	var sql []string
	for _, key := range identity[1].Secret.Items {
		if key.Key != key.Path {
			t.Fatal("identity projection redirects a credential")
		}
		if strings.HasPrefix(key.Key, "sql-") {
			sql = append(sql, key.Key)
		}
	}
	if !reflect.DeepEqual(sql, []string{"sql-enrollment.json", "sql-audit.json", "sql-activation.json", "sql-registry.json", "sql-routing.json", "sql-native-read.json"}) {
		t.Fatal("identity startup received worker or public SQL authority", sql)
	}
	v, mount := pod.Volumes[1], pod.Containers[0].VolumeMounts[1]
	if v.Secret == nil || v.Secret.SecretName != contracts.OwnerObservationProjectionName(p.InstallationID) || v.Secret.Optional == nil || !*v.Secret.Optional || v.Secret.DefaultMode == nil || *v.Secret.DefaultMode != 0440 || len(v.Secret.Items) != 0 || mount.Name != v.Name || mount.MountPath != contracts.OwnerObservationProjectionRoot || !mount.ReadOnly || mount.SubPath != "" || mount.SubPathExpr != "" {
		t.Fatal("observation catalog is not independently mounted")
	}
	// ADR-184: the public root projects exactly the immutable product role
	// projection and the operator Secret, both optional until written.
	v, mount = pod.Volumes[2], pod.Containers[0].VolumeMounts[2]
	if v.Projected == nil || v.Projected.DefaultMode == nil || *v.Projected.DefaultMode != 0440 || len(v.Projected.Sources) != 2 || mount.Name != v.Name || mount.MountPath != contracts.OwnerPublicProjectionRoot || !mount.ReadOnly || mount.SubPath != "" || strings.HasPrefix(mount.MountPath, contracts.OwnerDeploymentRoot+"/") {
		t.Fatal("public projection is not independently mounted")
	}
	for i, name := range []string{contracts.PublicRuntimeProjectionName(p.InstallationID), contracts.OwnerPublicProjectionName(p.InstallationID)} {
		s := v.Projected.Sources[i].Secret
		if s == nil || s.Name != name || s.Optional == nil || !*s.Optional || len(s.Items) != 0 {
			t.Fatal("public projection source changed", i)
		}
	}
	var secretRules int
	for _, rule := range w.Role.Rules {
		if !slices.Contains(rule.Resources, "secrets") {
			continue
		}
		secretRules++
		if !reflect.DeepEqual(rule.Verbs, []string{"get"}) || !reflect.DeepEqual(rule.ResourceNames, []string{p.Credentials, "asservat-runtime-resources-" + strings.ReplaceAll(p.InstallationID, "-", ""), contracts.OwnerObservationProjectionName(p.InstallationID), contracts.OwnerPublicProjectionName(p.InstallationID), contracts.PublicRuntimeProjectionName(p.InstallationID)}) {
			t.Fatal("projection proof granted broader Secret access")
		}
	}
	if secretRules != 1 || !reflect.DeepEqual(w.ClusterRole, legacy.ClusterRole) {
		t.Fatal("unexpected authorization expansion")
	}
	if len(w.Service.Spec.Ports) != 3 || w.Service.Spec.Ports[1].Port != contracts.OwnerInstalledNativePort || w.Service.Spec.Ports[2].Port != contracts.OwnerInstalledPublicPort {
		t.Fatal("installed listener ports are not fixed before original claims")
	}
	// Mutating an installed result must not alter an independently generated
	// legacy template or another caller's provider list.
	pod.Volumes[0].Projected.Sources[1].Secret.Items[0].Key = "changed"
	again, err := BuildOwnerWorkload(p)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(again)
	if err != nil || string(before) != string(after) {
		t.Fatal("installed builder changed legacy serialized template", err)
	}
}

func TestInstalledOwnerRejectsAlternateCompartmentNames(t *testing.T) {
	for _, field := range []string{"name", "account", "configuration", "credentials", "guard", "installation"} {
		t.Run(field, func(t *testing.T) {
			p := installedOwnerPlan()
			switch field {
			case "name":
				p.Name = "other-owner"
			case "account":
				p.ServiceAccount = "other-account"
			case "configuration":
				p.Configuration = "other-inputs"
			case "credentials":
				p.Credentials = "other-providers"
			case "guard":
				p.WorkloadGuard = "other-guard"
			case "installation":
				p.InstallationID = ownerID(2)
			}
			if _, err := BuildInstalledOwnerWorkload(p); err == nil {
				t.Fatal("alternate compartment accepted")
			}
		})
	}
}
