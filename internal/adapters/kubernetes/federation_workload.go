package kubernetes

import (
	"encoding/hex"
	"encoding/json"
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

// FederationWorkload is the installed hub-federation (ADR-193): its immutable
// inputs, Deployment, L4 Service and narrow RBAC. The account and the audit
// Secret already exist (EnsureFederationIdentity).
type FederationWorkload struct {
	Inputs         *core.ConfigMap
	Deployment     *apps.Deployment
	Service        *core.Service
	Role           *rbac.Role
	Binding        *rbac.RoleBinding
	ClusterRole    *rbac.ClusterRole
	ClusterBinding *rbac.ClusterRoleBinding
}

// FederationWorkloadName is the federation Deployment, Service and inputs name.
func FederationWorkloadName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-federation"
}

// BuildFederationWorkload builds the federation from its exact deployment
// input. It reads the owner guard's pins for its own RBAC: the guard proof
// reads the hub namespace and guard, and its named dry-run probe of the owner
// Deployment must be denied by that guard.
// nodePort, when nonzero, pins the NodePort so the operator's endpoint is
// known before the Service exists (ADR-193).
func BuildFederationWorkload(namespace, image, ownerDeployment, ownerServiceAccount string, d contracts.FederationDeployment, serviceTypeName string, nodePort int32) (*FederationWorkload, error) {
	serviceType := core.ServiceType(serviceTypeName)
	a, o := d.ProviderAuthentication, d.Owner
	if a == nil || o == nil || !authorization.UUID(d.InstallationID) || len(validation.IsDNS1123Label(namespace)) != 0 || a.Namespace.Name != namespace || o.Namespace.Name != namespace ||
		a.ServiceAccount.Name != contracts.FederationServiceAccountName(d.InstallationID) || len(validation.IsDNS1123Subdomain(ownerDeployment)) != 0 || len(validation.IsDNS1123Subdomain(ownerServiceAccount)) != 0 || (serviceType != core.ServiceTypeNodePort && serviceType != core.ServiceTypeLoadBalancer) || d.Port != contracts.FederationPort ||
		nodePort != 0 && (serviceType != core.ServiceTypeNodePort || nodePort < 30000 || nodePort > 32767) {
		return nil, cfg.ErrInvalid
	}
	parts := strings.Split(image, "@sha256:")
	if len(parts) != 2 || !hubWorkerImageRepository.MatchString(parts[0]) || len(parts[0]) > 384 || len(parts[1]) != 64 || strings.ContainsAny(image, " \t\r\n") {
		return nil, cfg.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[1]); err != nil || strings.ToLower(parts[1]) != parts[1] {
		return nil, cfg.ErrInvalid
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > contracts.FederationDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	name := FederationWorkloadName(d.InstallationID)
	inputs := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: name + "-inputs", Namespace: namespace}, Immutable: ptr.To(true), Data: map[string]string{"federation.json": string(raw)}}
	sqlFiles := []core.KeyToPath{{Key: contracts.FederationAuditKeysFile, Path: contracts.FederationAuditKeysFile}}
	for _, purpose := range contracts.PublicRuntimeFederationPurposes() {
		sqlFiles = append(sqlFiles, core.KeyToPath{Key: "sql-federation-" + purpose + ".json", Path: "sql-federation-" + purpose + ".json"})
	}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: inputs.Name}, Items: []core.KeyToPath{{Key: "federation.json", Path: "federation.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.FederationRuntimeProjectionName(d.InstallationID)}, Items: sqlFiles, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: a.AuditCredentials.Name}, Items: []core.KeyToPath{{Key: contracts.FederationProviderAuditCredentialFile, Path: "audit-storage.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.FederationServingSecretName(d.InstallationID)}, Items: []core.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.FederationProviderTokenFile, Audience: contracts.FederationProviderAudience(d.InstallationID, d.ClusterID), ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-observer.token", ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-probe.token", ExpirationSeconds: ptr.To(int64(600))}},
	}
	labels := map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "hub-federation", "asservat.io/workload": name}
	selector := map[string]string{"asservat.io/private-role": "hub-federation", "asservat.io/workload": name}
	deployment := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: apps.DeploymentSpec{
		Replicas: ptr.To(int32(1)), Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Selector: &meta.LabelSelector{MatchLabels: selector},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyAlways, ServiceAccountName: a.ServiceAccount.Name, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(40)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "federation", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "hub-federation"},
				SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
				Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("100m"), core.ResourceMemory: resource.MustParse("128Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("512Mi")}},
				Ports:           []core.ContainerPort{{Name: "federation", ContainerPort: contracts.FederationPort, Protocol: core.ProtocolTCP}},
				VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: contracts.FederationDeploymentRoot, ReadOnly: true}},
			}},
			Volumes: []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		}},
	}}
	service := &core.Service{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: core.ServiceSpec{Type: serviceType, Selector: selector,
		Ports: []core.ServicePort{{Name: "federation", Port: contracts.FederationPort, TargetPort: intstr.FromInt32(contracts.FederationPort), NodePort: nodePort, Protocol: core.ProtocolTCP}}}}
	// The owner guard proof (ADR-172 owner reads) and owner discovery only.
	role := &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get"}},
		// OwnerEndpoints independently checks the original owner account UID.
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{ownerServiceAccount}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets", "deployments"}, Verbs: []string{"get"}},
		// A dry-run probe target only: the owner guard denies every real write.
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{ownerDeployment}, Verbs: []string{"update"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
	}}
	clusterName := "asservat." + namespace + "." + name
	cluster := &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{o.WorkloadGuard.Name}, Verbs: []string{"get"}},
	}}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: a.ServiceAccount.Name, Namespace: namespace}}
	return &FederationWorkload{Inputs: inputs, Deployment: deployment, Service: service, Role: role,
		Binding:        &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}},
		ClusterRole:    cluster,
		ClusterBinding: &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}}}, nil
}
