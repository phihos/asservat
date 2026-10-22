package kubernetes

import (
	"encoding/hex"
	"strings"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

const InitialBootstrapRunnerInputAnnotation = "asservat.io/bootstrap-input"
const InitialBootstrapRunnerProfile = "four-command/v1"
const InitialInstallerRunnerProfile = "five-command/v1"

// Static orchestration only. This contains no UID, credential or effect claim.
// Helm renders this exact fixed profile; positive-terminal resume rechecks it.
type InitialBootstrapRunnerPlan struct {
	Namespace, Name, Image, InputDigest                            string
	ProducerSecret, SchemaSecret, RetirementSecret, RegistrySecret string
	ProbeAudience                                                  string
	ContinuationDigest                                             string
}

func BuildInitialBootstrapRunner(p InitialBootstrapRunnerPlan) (*core.Pod, error) {
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(p.Name) > 30 || len(validation.IsDNS1123Label(p.Name)) != 0 || !preparationDigestValid(p.InputDigest) || p.ProbeAudience != "" && !identity.Text(p.ProbeAudience, 256) {
		return nil, cfg.ErrInvalid
	}
	for _, n := range []string{p.ProducerSecret, p.SchemaSecret, p.RetirementSecret} {
		if len(validation.IsDNS1123Subdomain(n)) != 0 {
			return nil, cfg.ErrInvalid
		}
	}
	if p.RegistrySecret != "" && len(validation.IsDNS1123Subdomain(p.RegistrySecret)) != 0 {
		return nil, cfg.ErrInvalid
	}
	if p.ContinuationDigest != "" && !preparationDigestValid(p.ContinuationDigest) {
		return nil, cfg.ErrInvalid
	}
	parts := strings.Split(p.Image, "@sha256:")
	if len(parts) != 2 || len(parts[0]) > 384 || !hubWorkerImageRepository.MatchString(parts[0]) || len(parts[1]) != 64 || strings.ToLower(parts[1]) != parts[1] {
		return nil, cfg.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return nil, cfg.ErrInvalid
	}
	public := core.VolumeProjection{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: initialBootstrapRunnerInputName(p.Name, p.InputDigest)}, Items: []core.KeyToPath{{Key: "bootstrap.json", Path: "bootstrap.json"}}, Optional: ptr.To(false)}}
	token := core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "administrator-token", Audience: p.ProbeAudience, ExpirationSeconds: ptr.To(int64(600))}}
	ca := core.VolumeProjection{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: "kube-root-ca.crt"}, Items: []core.KeyToPath{{Key: "ca.crt", Path: "kube-ca.crt"}}, Optional: ptr.To(true)}}
	inputs := func(name string, keys []string, registry bool) core.VolumeSource {
		items := []core.KeyToPath{}
		for _, key := range keys {
			items = append(items, core.KeyToPath{Key: key, Path: key})
		}
		sources := []core.VolumeProjection{public, token, ca, {Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: name}, Items: items, Optional: ptr.To(true)}}}
		if registry && p.RegistrySecret != "" {
			sources = append(sources, core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: p.RegistrySecret}, Items: []core.KeyToPath{{Key: core.DockerConfigJsonKey, Path: core.DockerConfigJsonKey}}, Optional: ptr.To(true)}})
		}
		return core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: sources}}
	}
	memory := resource.MustParse("8Mi")
	volumes := []core.Volume{
		{Name: "scratch", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{Medium: core.StorageMediumMemory, SizeLimit: &memory}}},
		{Name: "producer-input", VolumeSource: inputs(p.ProducerSecret, []string{"postgres-administrator.json", "provider-material.json"}, true)},
		{Name: "retirement-input", VolumeSource: inputs(p.RetirementSecret, []string{"postgres-administrator.json"}, false)},
		{Name: "ddl-input", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: p.SchemaSecret, DefaultMode: ptr.To(int32(0440)), Optional: ptr.To(true), Items: []core.KeyToPath{{Key: "postgres-ddl.json", Path: "postgres-ddl.json"}}}}},
	}
	scratch := core.VolumeMount{Name: "scratch", MountPath: "/run/asservat/initial-bootstrap-work"}
	container := func(name, command string, mounts ...core.VolumeMount) core.Container {
		return core.Container{Name: name, Image: p.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", command}, VolumeMounts: mounts, SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), ReadOnlyRootFilesystem: ptr.To(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("20m"), core.ResourceMemory: resource.MustParse("32Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("256Mi")}}}
	}
	producer := container("produce", "initial-bootstrap", scratch, core.VolumeMount{Name: "producer-input", MountPath: "/run/asservat/initial-bootstrap", ReadOnly: true})
	schema := container("schema", "initial-bootstrap-schema", core.VolumeMount{Name: "scratch", MountPath: "/run/asservat/initial-schema", SubPath: "projection/schema", ReadOnly: true}, core.VolumeMount{Name: "ddl-input", MountPath: "/run/asservat/initial-schema-private", ReadOnly: true})
	prepare := container("prepare", "initial-bootstrap-prepare", core.VolumeMount{Name: "scratch", MountPath: "/run/asservat/initial-preparer", SubPath: "projection/preparer", ReadOnly: true})
	retire := container("retire", "initial-bootstrap-retire", scratch, core.VolumeMount{Name: "retirement-input", MountPath: "/run/asservat/initial-bootstrap", ReadOnly: true})
	pod := &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: p.Name + "-bootstrap", Namespace: p.Namespace, Labels: map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "bootstrap-runner"}, Annotations: map[string]string{"helm.sh/hook": "post-install,post-upgrade", "helm.sh/hook-delete-policy": "hook-succeeded", "asservat.io/bootstrap-runner": InitialBootstrapRunnerProfile, InitialBootstrapRunnerInputAnnotation: p.InputDigest}}, Spec: core.PodSpec{ServiceAccountName: p.Name + "-bootstrap-runner", AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyNever, ActiveDeadlineSeconds: ptr.To(int64(1800)), TerminationGracePeriodSeconds: ptr.To(int64(15)), SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), FSGroupChangePolicy: ptr.To(core.FSGroupChangeOnRootMismatch), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}, Volumes: volumes, InitContainers: []core.Container{producer, schema, prepare}, Containers: []core.Container{retire}}}
	if p.RegistrySecret != "" {
		pod.Spec.ImagePullSecrets = []core.LocalObjectReference{{Name: p.RegistrySecret}}
	}
	if p.ContinuationDigest != "" {
		pod.Annotations["asservat.io/bootstrap-runner"] = InitialInstallerRunnerProfile
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, retire)
		pod.Spec.Containers = []core.Container{container("continue", "installer-continue",
			core.VolumeMount{Name: "scratch", MountPath: "/run/asservat/initial-preparer", SubPath: "projection/preparer", ReadOnly: true},
			core.VolumeMount{Name: "continuation-input", MountPath: "/run/asservat/installer-continue", ReadOnly: true})}
		pod.Spec.Volumes = append(pod.Spec.Volumes, core.Volume{Name: "continuation-input", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: []core.VolumeProjection{
			{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: initialBootstrapContinuationInputName(p.Name, p.ContinuationDigest)}, Items: []core.KeyToPath{{Key: "continuation.json", Path: "continuation.json"}}, Optional: ptr.To(false)}},
			token,
			{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: p.ProducerSecret}, Items: []core.KeyToPath{{Key: "postgres-administrator.json", Path: "postgres-administrator.json"}}, Optional: ptr.To(false)}},
		}}}})
	}
	return pod, nil
}

// A retained runner always names its original immutable public input. Changed
// Helm values create another nonsecret snapshot, never update the old one.
func initialBootstrapRunnerInputName(name, digest string) string {
	return name + "-bootstrap-input." + digest[:32] + "." + digest[32:]
}

func initialBootstrapContinuationInputName(name, digest string) string {
	return name + "-continuation." + digest[:32]
}
