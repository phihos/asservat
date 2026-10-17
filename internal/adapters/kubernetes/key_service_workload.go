package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// BuildKeyServiceWorkload builds the installed key service (ADR-198) from its
// exact deployment input: the federation's object set, ensured the same way
// (EnsureFederationWorkload). Only this Pod mounts the key-service SQL logins
// and serving key; it reads the root key Secret through the API by name.
func BuildKeyServiceWorkload(namespace, image string, d contracts.KeyServiceDeployment, keySecret, serviceTypeName string, nodePort int32) (*FederationWorkload, error) {
	serviceType := core.ServiceType(serviceTypeName)
	if !authorization.UUID(d.InstallationID) || len(validation.IsDNS1123Label(namespace)) != 0 || d.Namespace.Name != namespace || d.Port != contracts.KeyServicePort || d.KeySource.Name == "" || len(validation.IsDNS1123Subdomain(keySecret)) != 0 ||
		(serviceType != core.ServiceTypeNodePort && serviceType != core.ServiceTypeLoadBalancer) || nodePort != 0 && (serviceType != core.ServiceTypeNodePort || nodePort < 30000 || nodePort > 32767) {
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
	if err != nil || len(raw) > contracts.KeyServiceDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	name := contracts.KeyServiceName(d.InstallationID)
	inputs := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: name + "-inputs", Namespace: namespace}, Immutable: ptr.To(true), Data: map[string]string{"key-service.json": string(raw)}}
	var sqlFiles []core.KeyToPath
	for _, purpose := range contracts.PublicRuntimeKeyServicePurposes() {
		sqlFiles = append(sqlFiles, core.KeyToPath{Key: "sql-" + purpose + ".json", Path: "sql-" + purpose + ".json"})
	}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: inputs.Name}, Items: []core.KeyToPath{{Key: "key-service.json", Path: "key-service.json"}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.KeyServiceRuntimeProjectionName(d.InstallationID)}, Items: sqlFiles, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.KeyServiceServingSecretName(d.InstallationID)}, Items: []core.KeyToPath{{Key: "tls.crt", Path: "tls.crt"}, {Key: "tls.key", Path: "tls.key"}}, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: "kube-observer.token", ExpirationSeconds: ptr.To(int64(600))}},
	}
	labels := map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "key-service", "asservat.io/workload": name}
	selector := map[string]string{"asservat.io/private-role": "key-service", "asservat.io/workload": name}
	deployment := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: apps.DeploymentSpec{
		Replicas: ptr.To(int32(1)), Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Selector: &meta.LabelSelector{MatchLabels: selector},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyAlways, ServiceAccountName: name, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(15)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "key-service", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "key-service"},
				SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
				Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("50m"), core.ResourceMemory: resource.MustParse("64Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("500m"), core.ResourceMemory: resource.MustParse("256Mi")}},
				Ports:           []core.ContainerPort{{Name: "key-service", ContainerPort: contracts.KeyServicePort, Protocol: core.ProtocolTCP}},
				VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: contracts.KeyServiceDeploymentRoot, ReadOnly: true}},
			}},
			Volumes: []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		}},
	}}
	service := &core.Service{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: core.ServiceSpec{Type: serviceType, Selector: selector,
		Ports: []core.ServicePort{{Name: "key-service", Port: contracts.KeyServicePort, TargetPort: intstr.FromInt32(contracts.KeyServicePort), NodePort: nodePort, Protocol: core.ProtocolTCP}}}}
	// Named reads of the key configuration and Secret only (ADR-067).
	role := &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{d.KeySource.Name}, Verbs: []string{"get"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{keySecret}, Verbs: []string{"get"}},
	}}
	clusterName := "asservat." + namespace + "." + name
	cluster := &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get"}},
	}}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: namespace}}
	return &FederationWorkload{Inputs: inputs, Deployment: deployment, Service: service, Role: role,
		Binding:        &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}},
		ClusterRole:    cluster,
		ClusterBinding: &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}}}, nil
}

// EnsureKeyServiceAccount creates the key service's own account without an
// automounted token, or reopens it unchanged.
func EnsureKeyServiceAccount(ctx context.Context, config *rest.Config, namespace, installation string) error {
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	accounts := api.CoreV1().ServiceAccounts(namespace)
	name := contracts.KeyServiceName(installation)
	a, err := accounts.Create(call, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if a, err = accounts.Get(call, name, meta.GetOptions{}); err == nil && (a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken || a.DeletionTimestamp != nil) {
			return cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(a.UID)) {
		return cfg.ErrUnavailable
	}
	return nil
}
