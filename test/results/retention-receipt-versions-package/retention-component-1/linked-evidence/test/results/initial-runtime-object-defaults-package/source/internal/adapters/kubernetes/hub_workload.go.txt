package kubernetes

import (
	"encoding/hex"
	"regexp"
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

var hubWorkerImageRepository = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[0-9]+/[a-z0-9][a-z0-9._/-]*)?$`)

// HubWorkerWorkloadPlan is installation-owned composition, never a developer
// selector. ConfigMap and Secret contents are provisioned separately and are not
// copied into Deployment annotations, environment or Helm release values.
type HubWorkerWorkloadPlan struct {
	Namespace, Name, ServiceAccount, Configuration, Credentials, Image string
	FleetSource, OwnerSource, FleetGuard, OwnerGuard, LeaderLease      string
}

type HubWorkerWorkload struct {
	Deployment     *apps.Deployment
	Account        *core.ServiceAccount
	Role           *rbac.Role
	Binding        *rbac.RoleBinding
	ClusterRole    *rbac.ClusterRole
	ClusterBinding *rbac.ClusterRoleBinding
}

// BuildHubWorkerWorkload builds objects but never applies them or activates an
// installation. It starts at zero replicas; install protection and immutable
// inputs before an installer explicitly launches the protected process.
func BuildHubWorkerWorkload(p HubWorkerWorkloadPlan) (*HubWorkerWorkload, error) {
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1123Label(p.Name)) != 0 || p.FleetSource == p.OwnerSource || p.Configuration == p.FleetSource || p.Configuration == p.OwnerSource || p.FleetGuard == p.OwnerGuard {
		return nil, cfg.ErrInvalid
	}
	for _, name := range []string{p.ServiceAccount, p.Configuration, p.Credentials, p.FleetSource, p.OwnerSource, p.FleetGuard, p.OwnerGuard, p.LeaderLease} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, cfg.ErrInvalid
		}
	}
	parts := strings.Split(p.Image, "@sha256:")
	if len(parts) != 2 || !hubWorkerImageRepository.MatchString(parts[0]) || len(parts[0]) > 384 || len(parts[1]) != 64 || strings.ContainsAny(p.Image, " \t\r\n") {
		return nil, cfg.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[1]); err != nil || strings.ToLower(parts[1]) != parts[1] {
		return nil, cfg.ErrInvalid
	}
	labels := map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "hub-worker", "asservat.io/workload": p.Name}
	selector := map[string]string{"asservat.io/private-role": "hub-worker", "asservat.io/workload": p.Name}
	files := []core.KeyToPath{}
	for _, name := range []string{"sql-fleet.json", "sql-configuration.json", "sql-audit.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token"} {
		files = append(files, core.KeyToPath{Key: name, Path: name})
	}
	projections := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Configuration}, Items: []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Credentials}, Items: files, Optional: ptr.To(false)}},
	}
	// All three clients already execute in one process with access to every
	// credential file. Native projections use that Pod's account; separate
	// client facets and admission proofs do not require separate principals.
	for _, path := range []string{"kube-observer.token", "kube-probe.token", "kube-leader.token"} {
		projections = append(projections, core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: path, ExpirationSeconds: ptr.To(int64(600))}})
	}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: p.ServiceAccount, Namespace: p.Namespace}}
	clusterName := "asservat." + p.Namespace + "." + p.Name
	role := &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.FleetSource, p.OwnerSource}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{p.LeaderLease}, Verbs: []string{"get", "update"}},
	}}
	clusterRole := &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{p.FleetGuard, p.OwnerGuard}, Verbs: []string{"get"}},
	}}
	deployment := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: apps.SchemeGroupVersion.String(), Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Selector: &meta.LabelSelector{MatchLabels: selector}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
		EnableServiceLinks: ptr.To(false), RestartPolicy: core.RestartPolicyAlways, ServiceAccountName: p.ServiceAccount, AutomountServiceAccountToken: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(15)),
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Containers:      []core.Container{{Name: "worker", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "hub-worker"}, SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}, Resources: core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}}, VolumeMounts: []core.VolumeMount{{Name: "inputs", MountPath: contracts.HubWorkerDeploymentRoot, ReadOnly: true}}}},
		Volumes:         []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projections}}}},
	}}}}
	return &HubWorkerWorkload{Deployment: deployment, Account: &core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: p.ServiceAccount, Namespace: p.Namespace}, AutomountServiceAccountToken: ptr.To(false)}, Role: role, ClusterRole: clusterRole, Binding: &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: p.Name}}, ClusterBinding: &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: append([]rbac.Subject(nil), subjects...), RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}}}, nil
}
