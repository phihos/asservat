package kubernetes

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	core "k8s.io/api/core/v1"
)

// This checks the fixed builder against the actual native template matcher.
// Scalar API defaults below match the separately native-qualified inert-object
// roundtrip. This is a synthetic component check, not a Kubernetes API verdict.
func TestInstalledOwnerTemplateHasOriginalNativeTolerations(t *testing.T) {
	id := ownerID(7330)
	names := runtimeResourceNames(id)
	plan := OwnerWorkloadPlan{InstallationID: id, Namespace: "control", Name: names.Owner, ServiceAccount: names.Owner, Configuration: names.OwnerInputs, Credentials: names.OwnerProviders, WorkloadGuard: names.WorkloadGuard, Image: "registry.example.test/asservat@sha256:" + strings.Repeat("1", 64)}
	original, e := BuildOwnerWorkload(plan)
	if e != nil {
		t.Fatal(e)
	}
	legacy := preparationDigest(original)
	installed, e := BuildInstalledOwnerWorkload(plan)
	if e != nil {
		t.Fatal(e)
	}
	template := installed.Deployment.Spec.Template.DeepCopy()
	template.Spec.DNSPolicy = core.DNSClusterFirst
	template.Spec.SchedulerName = core.DefaultSchedulerName
	template.Spec.Containers[0].TerminationMessagePath = core.TerminationMessagePathDefault
	template.Spec.Containers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
	digest, e := ConnectorAPITemplateDigest(*template)
	if e != nil || digest == (artifact.Digest{}) {
		t.Fatal("fresh installed template cannot be pinned by existing native matcher", e)
	}
	if len(template.Spec.Tolerations) != 2 {
		t.Fatal("installed template has additional eviction permissions")
	}
	for _, key := range []string{"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"} {
		found := false
		for _, v := range template.Spec.Tolerations {
			found = found || v.Key == key && v.Operator == core.TolerationOpExists && v.Value == "" && v.Effect == core.TaintEffectNoExecute && v.TolerationSeconds != nil && *v.TolerationSeconds == 300
		}
		if !found {
			t.Fatal("original exact eviction bound missing", key)
		}
	}
	for name, change := range map[string]func(*core.PodTemplateSpec){
		"missing":                func(v *core.PodTemplateSpec) { v.Spec.Tolerations = nil },
		"duplicate":              func(v *core.PodTemplateSpec) { v.Spec.Tolerations = append(v.Spec.Tolerations, v.Spec.Tolerations[0]) },
		"longer":                 func(v *core.PodTemplateSpec) { *v.Spec.Tolerations[0].TolerationSeconds = 301 },
		"unbounded":              func(v *core.PodTemplateSpec) { v.Spec.Tolerations[0].TolerationSeconds = nil },
		"wrong-effect":           func(v *core.PodTemplateSpec) { v.Spec.Tolerations[0].Effect = core.TaintEffectNoSchedule },
		"changed-other-template": func(v *core.PodTemplateSpec) { v.Annotations = map[string]string{"unreviewed": "changed"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := template.DeepCopy()
			change(changed)
			got, err := ConnectorAPITemplateDigest(*changed)
			if err == nil && got == digest {
				t.Fatal("modified original template retained accepted native digest")
			}
			if name != "changed-other-template" && err == nil {
				t.Fatal("unqualified eviction interval accepted by matcher")
			}
		})
	}
	after, e := BuildOwnerWorkload(plan)
	if e != nil || len(after.Deployment.Spec.Template.Spec.Tolerations) != 0 || preparationDigest(after) != legacy {
		t.Fatal("fresh profile changed legacy builder or its omitted fields", e)
	}
}
