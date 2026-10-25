package kubernetes

import (
	"encoding/hex"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

// OwnerWorkloadPlan is the private owner compartment's compiled installation
// plan. It exposes no Pod template, credential contents, RBAC rules or route.
// Public/native projections are separate additions, never inferred from ports.
type OwnerWorkloadPlan struct {
	InstallationID, Namespace, Name, ServiceAccount  string
	Configuration, Credentials, WorkloadGuard, Image string
}

type OwnerWorkload struct {
	Deployment     *apps.Deployment
	Account        *core.ServiceAccount
	Service        *core.Service
	Role           *rbac.Role
	Binding        *rbac.RoleBinding
	ClusterRole    *rbac.ClusterRole
	ClusterBinding *rbac.ClusterRoleBinding
}

// BuildOwnerWorkload constructs the actual private hub-api workload with zero
// replicas. Creating it cannot bind a listener or enroll a process. Its original
// immutable inputs and complete role/provider graph must precede a separately
// acknowledged launch; an absent Secret is not treated as a scheduling fence.
func BuildOwnerWorkload(p OwnerWorkloadPlan) (*OwnerWorkload, error) {
	if !authorization.UUID(p.InstallationID) || len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(validation.IsDNS1035Label(p.Name)) != 0 || p.Configuration == p.Credentials {
		return nil, cfg.ErrInvalid
	}
	for _, name := range []string{p.ServiceAccount, p.Configuration, p.Credentials, p.WorkloadGuard} {
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
	labels := map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "hub-api", "asservat.io/workload": p.Name}
	selector := map[string]string{"asservat.io/private-role": "hub-api", "asservat.io/workload": p.Name}
	secretFiles := []core.KeyToPath{}
	for _, name := range []string{"sql-enrollment.json", "sql-audit.json", "sql-activation.json", "sql-registry.json", "sql-routing.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "owner-server-sign.token", "owner-client-sign.token"} {
		secretFiles = append(secretFiles, core.KeyToPath{Key: name, Path: name})
	}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Configuration}, Items: []core.KeyToPath{{Key: "deployment.json", Path: "deployment.json"}, {Key: "worker-controls.json", Path: "worker-controls.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: p.Credentials}, Items: secretFiles, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "owner-pod.token", Audience: OwnerEnrollmentAudience(p.InstallationID), ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-observer.token", ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-probe.token", ExpirationSeconds: ptr.To(int64(600))}},
	}
	deployment := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Spec: apps.DeploymentSpec{
		Replicas: ptr.To(int32(0)), Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Selector: &meta.LabelSelector{MatchLabels: selector},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyAlways, ServiceAccountName: p.ServiceAccount, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(15)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "hub", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "hub-api"},
				Env:             []core.EnvVar{{Name: contracts.OwnerPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}},
				SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
				Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("128Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("512Mi")}},
				Ports:           []core.ContainerPort{{Name: "owner", ContainerPort: 9443, Protocol: core.ProtocolTCP}},
				VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: contracts.OwnerDeploymentRoot, ReadOnly: true}},
			}},
			Volumes: []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		}},
	}}
	role := &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "serviceaccounts", "services"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets", "deployments"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{p.Name}, Verbs: []string{"update"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
		// ADR-227: the release record; read only.
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{contracts.ReleaseRecordName(p.InstallationID)}, Verbs: []string{"get"}},
	}}
	clusterName := "asservat." + p.Namespace + "." + p.Name
	cluster := &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{p.WorkloadGuard}, Verbs: []string{"get"}},
		{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
	}}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: p.ServiceAccount, Namespace: p.Namespace}}
	return &OwnerWorkload{
		Deployment: deployment,
		Account:    &core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: p.ServiceAccount, Namespace: p.Namespace}, AutomountServiceAccountToken: ptr.To(false)},
		Service:    &core.Service{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Spec: core.ServiceSpec{Type: core.ServiceTypeClusterIP, ClusterIP: core.ClusterIPNone, Selector: selector, Ports: []core.ServicePort{{Name: "owner", Port: 9443, TargetPort: intstr.FromInt32(9443), Protocol: core.ProtocolTCP}}}},
		Role:       role, ClusterRole: cluster,
		Binding:        &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name, Namespace: p.Namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: p.Name}},
		ClusterBinding: &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: append([]rbac.Subject(nil), subjects...), RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}},
	}, nil
}
