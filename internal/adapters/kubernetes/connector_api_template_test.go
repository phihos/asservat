package kubernetes

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func connectorAPITemplateFixture() (apps.Deployment, apps.ReplicaSet, core.Pod, artifact.Digest) {
	image := artifact.Digest{1}
	template := core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: map[string]string{"app": "connector"}}, Spec: core.PodSpec{
		ServiceAccountName: "connector", AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, DNSPolicy: core.DNSClusterFirst, SchedulerName: "default-scheduler", TerminationGracePeriodSeconds: ptr.To(int64(15)),
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Containers:      []core.Container{{Name: "connector", Image: "example.invalid/connector@sha256:01" + strings.Repeat("0", 62), Command: []string{"/asservat", "connector"}, ImagePullPolicy: core.PullIfNotPresent, TerminationMessagePath: core.TerminationMessagePathDefault, TerminationMessagePolicy: core.TerminationMessageReadFile, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, VolumeMounts: []core.VolumeMount{{Name: "credential", MountPath: "/run/asservat", ReadOnly: true}}}},
		Volumes:         []core.Volume{{Name: "credential", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: "original-connector-audience", ExpirationSeconds: ptr.To(int64(600)), Path: "token"}}}}}}},
		Tolerations:     []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}},
	}}
	d := apps.Deployment{Spec: apps.DeploymentSpec{Template: template}}
	r := apps.ReplicaSet{Spec: apps.ReplicaSetSpec{Template: *template.DeepCopy(), Selector: &meta.LabelSelector{MatchLabels: map[string]string{apps.DefaultDeploymentUniqueLabelKey: "6f56bd5c7"}}}}
	r.Spec.Template.Labels[apps.DefaultDeploymentUniqueLabelKey] = "6f56bd5c7"
	p := core.Pod{ObjectMeta: *r.Spec.Template.ObjectMeta.DeepCopy(), Spec: *r.Spec.Template.Spec.DeepCopy()}
	p.Spec.NodeName = "assigned-node"
	p.Spec.Priority = ptr.To(int32(0))
	p.Spec.PreemptionPolicy = ptr.To(core.PreemptLowerPriority)
	p.Spec.DeprecatedServiceAccount = "connector"
	return d, r, p, image
}

func TestOwnerAPIContextAllowancePreservesOmissionAndExactStatusBranch(t *testing.T) {
	p := cfg.OwnerWorkloadAdministration{Name: "owner-workload", Deployment: "connector", DeploymentUID: ownerID(1), ControlNamespace: cfg.NamespaceRef{Name: "owners", UID: ownerID(2)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}}
	// Compare the exact old serialized shape, including its original nil slices.
	legacy := struct {
		Name, Deployment, DeploymentUID string
		ControlNamespace                cfg.NamespaceRef
		Administrators                  []cfg.KubernetesActor
		ConfigurationProbes             []cfg.OwnerConfigurationProbe
		SchedulingLeases                []cfg.OwnerSchedulingLease
	}{p.Name, p.Deployment, p.DeploymentUID, p.ControlNamespace, p.Administrators, p.ConfigurationProbes, p.SchedulingLeases}
	b, _ := json.Marshal(p)
	old, _ := json.Marshal(legacy)
	if !bytes.Equal(b, old) {
		t.Fatal("omitted capability changes old bytes")
	}
	before, binding, e := OwnerWorkloadAdmission(p)
	if e != nil {
		t.Fatal(e)
	}
	p.APIContextStarts = &cfg.OwnerAPIContextStarts{CapacityAccount: "capacity", CapacityAccountUID: ownerID(3), ExecutionAccount: "connector", ExecutionAccountUID: ownerID(4)}
	after, other, e := OwnerWorkloadAdmission(p)
	if e != nil {
		t.Fatal(e)
	}
	base := before.Spec.Validations[0].Expression
	added := strings.TrimSuffix(after.Spec.Validations[0].Expression, " || "+base)
	if added == after.Spec.Validations[0].Expression || !strings.Contains(added, "request.operation == 'CREATE' && variables.subResource == ''") || !strings.Contains(added, "request.operation == 'UPDATE' && variables.subResource == 'status'") || strings.Contains(added, "DELETE") || strings.Contains(added, "CONNECT") || !strings.Contains(added, "request.userInfo.uid == "+ownerCELString(ownerID(3))) || !strings.Contains(added, "request.userInfo.uid == "+ownerCELString(ownerID(4))) {
		t.Fatalf("wrong closed branch: %s", added)
	}
	b, _ = json.Marshal(binding)
	old, _ = json.Marshal(other)
	if !bytes.Equal(b, old) {
		t.Fatal("optional capability changed binding")
	}
	p.APIContextStarts.ExecutionAccount = p.APIContextStarts.CapacityAccount
	if _, _, e = OwnerWorkloadAdmission(p); e == nil {
		t.Fatal("shared capacity/execution actor accepted")
	}
}
