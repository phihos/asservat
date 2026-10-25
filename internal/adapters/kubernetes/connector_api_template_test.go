package kubernetes

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
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
func TestConnectorAPITemplatePinsEverySecurityAndInputField(t *testing.T) {
	d, r, p, image := connectorAPITemplateFixture()
	digest, e := ConnectorAPITemplateDigest(d.Spec.Template)
	if e != nil {
		t.Fatal(e)
	}
	if e = connectorAPITemplateMatch(&d, &r, &p, digest, image, nil, 0); e != nil {
		t.Fatalf("closed scheduler/default differences: %v", e)
	}
	for name, change := range map[string]func(*apps.Deployment, *apps.ReplicaSet, *core.Pod){
		"image": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers[0].Image = "different@sha256:" + strings.Repeat("a", 64)
		},
		"command": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers[0].Command = []string{"/changed"}
		},
		"sidecar": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, core.Container{Name: "injected"})
		},
		"init": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.InitContainers = []core.Container{{Name: "injected"}}
		},
		"ephemeral": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "injected"}}}
		},
		"automount": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.AutomountServiceAccountToken = ptr.To(true)
		},
		"automatic-token-volume": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, core.Volume{Name: "kube-api-access-extra"})
		},
		"token-audience": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "different"
		},
		"token-lifetime": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.ExpirationSeconds = ptr.To(int64(3600))
		},
		"mount": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
		},
		"privilege": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = ptr.To(true)
		},
		"fs-group": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.SecurityContext.FSGroup = ptr.To(int64(0))
		},
		"service-links": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) { p.Spec.EnableServiceLinks = ptr.To(true) },
		"priority":      func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) { p.Spec.Priority = ptr.To(int32(100)) },
		"scheduler":     func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) { p.Spec.SchedulerName = "different" },
		"toleration-change": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Tolerations[0].TolerationSeconds = nil
		},
		"extra-toleration": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Spec.Tolerations = append(p.Spec.Tolerations, core.Toleration{Operator: core.TolerationOpExists})
		},
		"annotation": func(_ *apps.Deployment, _ *apps.ReplicaSet, p *core.Pod) {
			p.Annotations = map[string]string{"inject": "true"}
		},
		"rs-template": func(_ *apps.Deployment, r *apps.ReplicaSet, _ *core.Pod) {
			r.Spec.Template.Spec.Containers[0].Args = []string{"changed"}
		},
		"rs-hash": func(_ *apps.Deployment, r *apps.ReplicaSet, _ *core.Pod) {
			r.Spec.Template.Labels[apps.DefaultDeploymentUniqueLabelKey] = "other"
		},
		"deployment-template": func(d *apps.Deployment, _ *apps.ReplicaSet, _ *core.Pod) {
			d.Spec.Template.Annotations = map[string]string{"new": "value"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dc, rc, pc := d.DeepCopy(), r.DeepCopy(), p.DeepCopy()
			change(dc, rc, pc)
			if connectorAPITemplateMatch(dc, rc, pc, digest, image, nil, 0) == nil {
				t.Fatal("changed protected input accepted")
			}
		})
	}
	missing := d.Spec.Template.DeepCopy()
	missing.Spec.Tolerations = nil
	if _, e = ConnectorAPITemplateDigest(*missing); e == nil {
		t.Fatal("profile left eviction defaults to admission")
	}
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

func TestConnectorAPISettingsMaximumLegalInputsFit(t *testing.T) {
	id := ownerID(1)
	digest := strings.Repeat("a", 64)
	projection := compiler.ProjectionDigest()
	name := strings.Repeat("a", 253)
	p := contracts.ConnectorAPIContextSettings{Format: contracts.ConnectorAPIContextFormat, RootID: id, InstallationID: id, ClusterID: id, IssuerEpoch: id, ConnectorRevision: contracts.APIContextRevision{UID: id, Generation: 2147483647, Digest: digest}, Namespace: strings.Repeat("n", 63), NamespaceUID: id, Account: name, AccountUID: id, Deployment: name, DeploymentUID: id, ImageDigest: digest, TemplateDigest: digest, ProjectionDigest: hex.EncodeToString(projection[:]), WorkloadProtectionDigest: digest, CapacityAccount: strings.Repeat("b", 253), CapacityAccountUID: ownerID(2), StartGuard: contracts.ConnectorAPIStartGuard{Name: name, PolicyUID: id, PolicyGeneration: 2147483647, BindingUID: id, BindingResourceVersion: strings.Repeat(`"`, 128)}}
	for n := 0; n < 16; n++ {
		p.Inputs = append(p.Inputs, contracts.ConnectorAPIInput{Kind: "ConfigMap", Name: fmt.Sprintf("%02d", n) + strings.Repeat("a", 251), UID: id, ResourceVersion: strings.Repeat(`"`, 128)})
	}
	if !connectorAPISettingsValid(p) {
		t.Fatal("maximum legal fixture rejected")
	}
	encoded, e := contracts.EncodeConnectorAPIContextSettings(p)
	if e != nil {
		t.Fatal("maximum accepted settings do not fit bounded encoding", e)
	}
	if len(encoded) > contracts.ConnectorAPIContextSettingsBytes {
		t.Fatal("settings exceeded declared bound")
	}
	t.Logf("maximum first-profile settings: %d bytes", len(encoded))
	decoded, e := contracts.DecodeConnectorAPIContextSettings(encoded)
	if e != nil || !connectorAPISettingsValid(decoded) {
		t.Fatal("max settings cannot be read", e)
	}
	// A whole-object grant is a protected installer decision, not inferred
	// from a mount, key selection, object name or metadata response.
	p.Inputs[0].Kind = "Secret"
	if connectorAPISettingsValid(p) {
		t.Fatal("shared/unapproved Secret accepted")
	}
	p.Inputs[0].DedicatedToAPI = true
	if !connectorAPISettingsValid(p) {
		t.Fatal("dedicated role-owned Secret rejected")
	}
	p.Inputs[0].Kind = "ConfigMap"
	if connectorAPISettingsValid(p) {
		t.Fatal("Secret authority marker accepted on ConfigMap")
	}
	p.Inputs[0].DedicatedToAPI = false
	// The constructor still rejects unbounded input inventory before any API read.
	p.Inputs = append(p.Inputs, contracts.ConnectorAPIInput{Kind: "Secret", Name: "extra", UID: id, ResourceVersion: "1"})
	if connectorAPISettingsValid(p) {
		t.Fatal("seventeenth input accepted")
	}
	p.Inputs[0].Name = strings.Repeat("x", contracts.ConnectorAPIContextSettingsBytes)
	if _, e = contracts.EncodeConnectorAPIContextSettings(p); e == nil {
		t.Fatal("oversize settings encoded")
	}
}
