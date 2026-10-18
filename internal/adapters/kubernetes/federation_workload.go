package kubernetes

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"
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
func BuildFederationWorkload(namespace, image, ownerDeployment string, d contracts.FederationDeployment, serviceTypeName string, nodePort int32) (*FederationWorkload, error) {
	serviceType := core.ServiceType(serviceTypeName)
	a, o := d.ProviderAuthentication, d.Owner
	if a == nil || o == nil || !authorization.UUID(d.InstallationID) || len(validation.IsDNS1123Label(namespace)) != 0 || a.Namespace.Name != namespace || o.Namespace.Name != namespace ||
		a.ServiceAccount.Name != contracts.FederationServiceAccountName(d.InstallationID) || len(validation.IsDNS1123Subdomain(ownerDeployment)) != 0 || (serviceType != core.ServiceTypeNodePort && serviceType != core.ServiceTypeLoadBalancer) || d.Port != contracts.FederationPort ||
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

const federationTemplateAnnotation = "asservat.io/federation-template"

// EnsureFederationWorkload creates every federation object, or reopens one
// only when its recorded template digest is exactly this build's. It never
// updates an existing object; a different template is a change.
func EnsureFederationWorkload(ctx context.Context, config *rest.Config, w *FederationWorkload) error {
	if ctx == nil || config == nil || w == nil {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	stamp := func(m *meta.ObjectMeta, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return cfg.ErrInvalid
		}
		d := sha256.Sum256(b)
		m.Annotations = map[string]string{federationTemplateAnnotation: hex.EncodeToString(d[:])}
		return nil
	}
	same := func(got, want meta.ObjectMeta) bool {
		return got.DeletionTimestamp == nil && got.Annotations[federationTemplateAnnotation] == want.Annotations[federationTemplateAnnotation]
	}
	ns := w.Deployment.Namespace
	if err = stamp(&w.Inputs.ObjectMeta, w.Inputs.Data); err != nil {
		return err
	}
	if c, e := api.CoreV1().ConfigMaps(ns).Create(call, w.Inputs, meta.CreateOptions{}); apierrors.IsAlreadyExists(e) {
		if c, e = api.CoreV1().ConfigMaps(ns).Get(call, w.Inputs.Name, meta.GetOptions{}); e == nil && !same(c.ObjectMeta, w.Inputs.ObjectMeta) {
			return cfg.ErrChanged
		}
	} else if e != nil {
		return cfg.ErrUnavailable
	}
	for _, step := range []func() error{
		func() error {
			r, e := api.RbacV1().Roles(ns).Create(call, w.Role, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if r, e = api.RbacV1().Roles(ns).Get(call, w.Role.Name, meta.GetOptions{}); e == nil && !reflect.DeepEqual(r.Rules, w.Role.Rules) {
					return cfg.ErrChanged
				}
			}
			return e
		},
		func() error {
			b, e := api.RbacV1().RoleBindings(ns).Create(call, w.Binding, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if b, e = api.RbacV1().RoleBindings(ns).Get(call, w.Binding.Name, meta.GetOptions{}); e == nil && (!reflect.DeepEqual(b.Subjects, w.Binding.Subjects) || b.RoleRef != w.Binding.RoleRef) {
					return cfg.ErrChanged
				}
			}
			return e
		},
		func() error {
			r, e := api.RbacV1().ClusterRoles().Create(call, w.ClusterRole, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if r, e = api.RbacV1().ClusterRoles().Get(call, w.ClusterRole.Name, meta.GetOptions{}); e == nil && !reflect.DeepEqual(r.Rules, w.ClusterRole.Rules) {
					return cfg.ErrChanged
				}
			}
			return e
		},
		func() error {
			b, e := api.RbacV1().ClusterRoleBindings().Create(call, w.ClusterBinding, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if b, e = api.RbacV1().ClusterRoleBindings().Get(call, w.ClusterBinding.Name, meta.GetOptions{}); e == nil && (!reflect.DeepEqual(b.Subjects, w.ClusterBinding.Subjects) || b.RoleRef != w.ClusterBinding.RoleRef) {
					return cfg.ErrChanged
				}
			}
			return e
		},
		func() error {
			if w.Service == nil { // the publisher serves nothing (ADR-203)
				return nil
			}
			if e := stamp(&w.Service.ObjectMeta, w.Service.Spec); e != nil {
				return e
			}
			s, e := api.CoreV1().Services(ns).Create(call, w.Service, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if s, e = api.CoreV1().Services(ns).Get(call, w.Service.Name, meta.GetOptions{}); e == nil && !same(s.ObjectMeta, w.Service.ObjectMeta) {
					return cfg.ErrChanged
				}
			}
			return e
		},
		func() error {
			if e := stamp(&w.Deployment.ObjectMeta, w.Deployment.Spec); e != nil {
				return e
			}
			d, e := api.AppsV1().Deployments(ns).Create(call, w.Deployment, meta.CreateOptions{})
			if apierrors.IsAlreadyExists(e) {
				if d, e = api.AppsV1().Deployments(ns).Get(call, w.Deployment.Name, meta.GetOptions{}); e == nil && !same(d.ObjectMeta, w.Deployment.ObjectMeta) {
					return cfg.ErrChanged
				}
			}
			return e
		},
	} {
		if e := step(); e != nil {
			if errors.Is(e, cfg.ErrChanged) || errors.Is(e, cfg.ErrInvalid) {
				return e
			}
			return cfg.ErrUnavailable
		}
	}
	return nil
}

// ReadFederationServingRoots reads the operator's federation TLS Secret and
// returns its CA roots for the offer. The certificate must name serverName
// and chain to those roots.
func ReadFederationServingRoots(ctx context.Context, config *rest.Config, namespace, installation, serverName string) ([][]byte, error) {
	if !authorization.UUID(installation) {
		return nil, cfg.ErrInvalid
	}
	return readServingRoots(ctx, config, namespace, contracts.FederationServingSecretName(installation), serverName)
}

// ReadKeyServiceServingRoots does the same for the key service's operator
// TLS Secret (ADR-198); serverName is its endpoint's host.
func ReadKeyServiceServingRoots(ctx context.Context, config *rest.Config, namespace, installation, serverName string) ([][]byte, error) {
	if !authorization.UUID(installation) {
		return nil, cfg.ErrInvalid
	}
	return readServingRoots(ctx, config, namespace, contracts.KeyServiceServingSecretName(installation), serverName)
}

func readServingRoots(ctx context.Context, config *rest.Config, namespace, secret, serverName string) ([][]byte, error) {
	if ctx == nil || config == nil || namespace == "" || serverName == "" {
		return nil, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	s, err := api.CoreV1().Secrets(namespace).Get(call, secret, meta.GetOptions{})
	if err != nil || s.Type != core.SecretTypeTLS || len(s.Data["tls.key"]) == 0 {
		return nil, cfg.ErrUnavailable
	}
	defer clear(s.Data["tls.key"])
	roots, err := pemRoots(s.Data["ca.crt"])
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, der := range roots {
		c, _ := x509.ParseCertificate(der)
		pool.AddCert(c)
	}
	block, _ := pem.Decode(s.Data["tls.crt"])
	if block == nil || len(roots) == 0 || len(roots) > 4 {
		return nil, cfg.ErrInvalid
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, cfg.ErrInvalid
	}
	return roots, nil
}

// PublishRegionalOffer writes the public, immutable regional offer (ADR-193):
// what a regional installer needs to write its connector source. It holds no
// credential and confers no enrollment authority; a reopened offer must match.
func PublishRegionalOffer(ctx context.Context, config *rest.Config, namespace string, offer contracts.RegionalOffer) error {
	if ctx == nil || config == nil || namespace == "" || offer.Format != contracts.RegionalOfferFormat || !authorization.UUID(offer.InstallationID) {
		return cfg.ErrInvalid
	}
	raw, err := json.Marshal(offer)
	if err != nil {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	want := &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: contracts.RegionalOfferName(offer.InstallationID)}, Immutable: ptr.To(true), Data: map[string]string{contracts.RegionalOfferFile: string(raw)}}
	got, err := api.CoreV1().ConfigMaps(namespace).Create(call, want, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if got, err = api.CoreV1().ConfigMaps(namespace).Get(call, want.Name, meta.GetOptions{}); err == nil && !reflect.DeepEqual(got.Data, want.Data) {
			return cfg.ErrChanged
		}
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

// pemRoots parses a PEM bundle of CA certificates into DER roots.
func pemRoots(bundle []byte) ([][]byte, error) {
	var roots [][]byte
	for rest := bundle; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return roots, nil
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if b.Type != "CERTIFICATE" || e != nil || !c.IsCA {
			return nil, cfg.ErrInvalid
		}
		roots = append(roots, b.Bytes)
	}
}
