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
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// PublisherIdentity is the publisher's account and its two empty operator
// credential Secrets (ADR-203). The account exists before the phase-3 artifact
// names it; the Secrets are filled from the phase-3 inbox.
type PublisherIdentity struct {
	Account, AuditCredentials, EvidenceCredentials contracts.WorkerObjectReference
}

// EnsurePublisherIdentity creates the fixed account and credential Secrets, or
// reopens them when they match exactly. It never updates an existing object.
func EnsurePublisherIdentity(ctx context.Context, config *rest.Config, namespace, installation string) (PublisherIdentity, error) {
	var out PublisherIdentity
	if ctx == nil || config == nil || namespace == "" || !authorization.UUID(installation) {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	accounts := api.CoreV1().ServiceAccounts(namespace)
	name := contracts.PublisherName(installation)
	a, err := accounts.Create(call, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if a, err = accounts.Get(call, name, meta.GetOptions{}); err == nil && (a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken || a.DeletionTimestamp != nil) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(a.UID)) {
		return out, cfg.ErrUnavailable
	}
	out.Account = contracts.WorkerObjectReference{Name: name, UID: string(a.UID)}
	secrets := api.CoreV1().Secrets(namespace)
	for _, s := range []struct {
		name string
		ref  *contracts.WorkerObjectReference
	}{{name + "-audit", &out.AuditCredentials}, {name + "-evidence", &out.EvidenceCredentials}} {
		v, err := secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: s.name}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			if v, err = secrets.Get(call, s.name, meta.GetOptions{}); err == nil && (v.Type != core.SecretTypeOpaque || v.DeletionTimestamp != nil || len(v.Data) > 1) {
				return PublisherIdentity{}, cfg.ErrChanged
			}
		}
		if err != nil || !authorization.UUID(string(v.UID)) {
			return PublisherIdentity{}, cfg.ErrUnavailable
		}
		*s.ref = contracts.WorkerObjectReference{Name: s.name, UID: string(v.UID)}
	}
	return out, nil
}

// BuildPublisherWorkload builds the installed publisher (ADR-203) from its exact
// deployment input: immutable inputs, a Deployment and narrow RBAC, ensured
// like the federation (EnsureFederationWorkload). It has no Service. Only this
// Pod mounts the publisher's SQL logins and the evidence read credential.
func BuildPublisherWorkload(namespace, image, ownerDeployment string, d contracts.PublisherDeployment, identity PublisherIdentity) (*FederationWorkload, error) {
	a, o := d.ProviderAuthentication, d.Owner
	name := contracts.PublisherName(d.InstallationID)
	if !authorization.UUID(d.InstallationID) || len(validation.IsDNS1123Label(namespace)) != 0 || d.Namespace.Name != namespace || a.Namespace.Name != namespace || o.Namespace.Name != namespace ||
		a.ServiceAccount != identity.Account || identity.Account.Name != name || len(validation.IsDNS1123Subdomain(ownerDeployment)) != 0 ||
		identity.AuditCredentials.Name != name+"-audit" || identity.EvidenceCredentials.Name != name+"-evidence" ||
		d.ClusterCatalog.Source.Name != contracts.OwnerClusterCatalogName(d.InstallationID) || d.ClusterCatalog.Guard.Name == "" || o.WorkloadGuard.Name == "" {
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
	if err != nil || len(raw) > contracts.PublisherDeploymentMaxBytes {
		return nil, cfg.ErrInvalid
	}
	inputs := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: name + "-inputs", Namespace: namespace}, Immutable: ptr.To(true), Data: map[string]string{contracts.PublisherDeploymentFile: string(raw)}}
	sqlFiles := []core.KeyToPath{{Key: contracts.PublisherCredentialManifestFile, Path: contracts.PublisherCredentialManifestFile}}
	for _, purpose := range contracts.PublicRuntimePublisherPurposes() {
		sqlFiles = append(sqlFiles, core.KeyToPath{Key: "sql-public-" + purpose + ".json", Path: "sql-public-" + purpose + ".json"})
	}
	projection := []core.VolumeProjection{
		{ConfigMap: &core.ConfigMapProjection{LocalObjectReference: core.LocalObjectReference{Name: inputs.Name}, Items: []core.KeyToPath{{Key: contracts.PublisherDeploymentFile, Path: contracts.PublisherDeploymentFile}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.PublisherRuntimeProjectionName(d.InstallationID)}, Items: sqlFiles, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: identity.AuditCredentials.Name}, Items: []core.KeyToPath{{Key: contracts.PublisherAuditCredential, Path: contracts.PublisherAuditCredential}}, Optional: ptr.To(false)}},
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: identity.EvidenceCredentials.Name}, Items: []core.KeyToPath{{Key: contracts.PublisherEvidenceCredential, Path: contracts.PublisherEvidenceCredential}}, Optional: ptr.To(false)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.PublisherProviderTokenFile, Audience: contracts.PublisherProviderAudience(d.InstallationID, d.ClusterID), ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.PublisherKubernetesToken, ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.PublisherProbeToken, ExpirationSeconds: ptr.To(int64(600))}},
	}
	labels := map[string]string{"app.kubernetes.io/name": "asservat", "asservat.io/private-role": "publisher", "asservat.io/workload": name}
	selector := map[string]string{"asservat.io/private-role": "publisher", "asservat.io/workload": name}
	deployment := &apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: apps.DeploymentSpec{
		Replicas: ptr.To(int32(1)), Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}, Selector: &meta.LabelSelector{MatchLabels: selector},
		Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyAlways, ServiceAccountName: name, AutomountServiceAccountToken: ptr.To(false), EnableServiceLinks: ptr.To(false), TerminationGracePeriodSeconds: ptr.To(int64(40)),
			SecurityContext: &core.PodSecurityContext{RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To(int64(65532)), RunAsGroup: ptr.To(int64(65532)), FSGroup: ptr.To(int64(65532)), SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
			Containers: []core.Container{{Name: "publisher", Image: image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/asservat", "publisher"},
				SecurityContext: &core.SecurityContext{ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
				Resources:       core.ResourceRequirements{Requests: core.ResourceList{core.ResourceCPU: resource.MustParse("50m"), core.ResourceMemory: resource.MustParse("128Mi")}, Limits: core.ResourceList{core.ResourceCPU: resource.MustParse("1"), core.ResourceMemory: resource.MustParse("512Mi")}},
				VolumeMounts:    []core.VolumeMount{{Name: "inputs", MountPath: contracts.PublisherDeploymentRoot, ReadOnly: true}},
			}},
			Volumes: []core.Volume{{Name: "inputs", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: projection}}}},
		}},
	}}
	// The owner guard proof (as the federation's) and the guarded catalog read
	// (as the hub-api's): get on the catalog and slot topologies, and update on
	// the catalog only as a dry-run probe target its guard denies.
	role := &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets", "deployments"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{ownerDeployment}, Verbs: []string{"update"}},
		{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{d.ClusterCatalog.Source.Name}, Verbs: []string{"get", "update"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: contracts.OwnerClusterTopologyNames(d.InstallationID), Verbs: []string{"get"}},
	}}
	clusterName := "asservat." + namespace + "." + name
	cluster := &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{namespace}, Verbs: []string{"get"}},
		{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{o.WorkloadGuard.Name, d.ClusterCatalog.Guard.Name}, Verbs: []string{"get"}},
	}}
	subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: namespace}}
	return &FederationWorkload{Inputs: inputs, Deployment: deployment, Role: role,
		Binding:        &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}},
		ClusterRole:    cluster,
		ClusterBinding: &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}}}, nil
}
