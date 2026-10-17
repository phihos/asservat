package kubernetes

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// CapacityProbeAccount is the hub cluster selector guard's dedicated probe
// ServiceAccount in its own empty namespace (ADR-190 decision 6).
const CapacityProbeAccount = "capacity-probe"

// CapacitySources are the hub-cluster capacity sources the continuation
// creates before the owner launch (ADR-190): the pool and policy guard, the
// hub cluster's selector guard with its dedicated probe namespace, and the
// processing source with its guard.
type CapacitySources struct {
	Guard            contracts.OwnerDeploymentGuard
	NamespaceGuard   contracts.OwnerDeploymentGuard
	ProbeNamespace   contracts.WorkerObjectReference
	ProbeAccount     contracts.WorkerObjectReference
	ProcessingSource contracts.WorkerObjectReference
	ProcessingGuard  contracts.OwnerDeploymentGuard
}

// CapacitySourceNames are the fixed names derived from the installation.
func CapacitySourceNames(installation string) (guard, namespaceGuard, probeNamespace, processingSource, processingGuard string) {
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	return prefix + "-capacity-guard", prefix + "-capacity-ns-guard", prefix + "-capacity-probe", installedProcessingSource(installation), prefix + "-processing-guard"
}

// EnsureCapacitySources creates or reopens these objects. Existing guards
// must match exactly; an existing probe namespace must carry none of the
// selector keys, and an existing processing source is kept as the
// administrator left it. Nothing existing is updated.
func EnsureCapacitySources(ctx context.Context, config *rest.Config, control cfg.NamespaceRef, installation string, admins []cfg.KubernetesActor, worker, owner contracts.WorkerObjectReference, keys []string, processing contracts.DownloadEnvironmentSettings) (CapacitySources, error) {
	var out CapacitySources
	if ctx == nil || config == nil || control.Name == "" || !authorization.UUID(control.UID) || !authorization.UUID(installation) || len(admins) == 0 || !installationRefValid(worker.Name, worker.UID) || !installationRefValid(owner.Name, owner.UID) || len(keys) == 0 {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	guardName, namespaceGuardName, probeName, sourceName, processingGuardName := CapacitySourceNames(installation)

	plan := cfg.CapacityAdministration{Name: guardName, ControlNamespace: control, Administrators: admins, StatusUsers: []string{}, ProbeAccount: cfg.NamespaceRef{Name: worker.Name, UID: worker.UID}}
	policy, binding, err := CapacityAdmission(plan)
	if err != nil {
		return out, err
	}
	if out.Guard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}

	if out.ProbeNamespace, out.ProbeAccount, err = ensureCapacityProbe(call, api, probeName, keys, control.Name, owner.Name); err != nil {
		return out, err
	}
	namespacePlan := cfg.CapacityNamespaceAdministration{Name: namespaceGuardName, Administrators: admins, Keys: keys,
		ProbeNamespace: cfg.NamespaceRef{Name: out.ProbeNamespace.Name, UID: out.ProbeNamespace.UID}, ProbeAccount: cfg.NamespaceRef{Name: out.ProbeAccount.Name, UID: out.ProbeAccount.UID}}
	if policy, binding, err = CapacityNamespaceAdmission(namespacePlan); err != nil {
		return out, err
	}
	if out.NamespaceGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}

	body, err := json.Marshal(processing)
	if err != nil || processing.Format != contracts.DownloadEnvironmentFormat || processing.InstallationID != installation {
		return out, cfg.ErrInvalid
	}
	source, err := api.CoreV1().ConfigMaps(control.Name).Create(call, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: sourceName}, Data: map[string]string{contracts.DownloadEnvironmentFile: string(body)}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		source, err = api.CoreV1().ConfigMaps(control.Name).Get(call, sourceName, meta.GetOptions{})
	}
	if err != nil || !authorization.UUID(string(source.UID)) || len(source.Data) != 1 || source.Data[contracts.DownloadEnvironmentFile] == "" {
		return out, cfg.ErrUnavailable
	}
	out.ProcessingSource = contracts.WorkerObjectReference{Name: source.Name, UID: string(source.UID)}
	if policy, binding, err = DownloadEnvironmentAdmission(cfg.ConfigMapAdministration{Name: processingGuardName, SourceName: sourceName, ControlNamespace: control, Administrators: admins}); err != nil {
		return out, err
	}
	if out.ProcessingGuard, err = ensureAdmissionGuard(call, api, policy, binding, admins); err != nil {
		return out, err
	}
	return out, nil
}

// ensureCapacityProbe creates the empty probe namespace, its probe account
// and the account's only right: get and update on that namespace.
func ensureCapacityProbe(call context.Context, api kubernetes.Interface, name string, keys []string, ownerNamespace, owner string) (contracts.WorkerObjectReference, contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	ns, err := api.CoreV1().Namespaces().Create(call, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		ns, err = api.CoreV1().Namespaces().Get(call, name, meta.GetOptions{})
	}
	if err != nil || !authorization.UUID(string(ns.UID)) || ns.DeletionTimestamp != nil {
		return zero, zero, cfg.ErrUnavailable
	}
	for _, k := range keys {
		if _, ok := ns.Labels[k]; ok {
			return zero, zero, cfg.ErrChanged
		}
	}
	account, err := api.CoreV1().ServiceAccounts(name).Create(call, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: CapacityProbeAccount}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		account, err = api.CoreV1().ServiceAccounts(name).Get(call, CapacityProbeAccount, meta.GetOptions{})
	}
	if err != nil || !authorization.UUID(string(account.UID)) {
		return zero, zero, cfg.ErrUnavailable
	}
	role := &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{name}, Verbs: []string{"get", "update"}}}}
	got, err := api.RbacV1().ClusterRoles().Create(call, role, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if got, err = api.RbacV1().ClusterRoles().Get(call, name, meta.GetOptions{}); err == nil && !reflect.DeepEqual(got.Rules, role.Rules) {
			return zero, zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, zero, cfg.ErrUnavailable
	}
	binding := &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: name, Name: CapacityProbeAccount}}}
	bound, err := api.RbacV1().ClusterRoleBindings().Create(call, binding, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if bound, err = api.RbacV1().ClusterRoleBindings().Get(call, name, meta.GetOptions{}); err == nil && (!reflect.DeepEqual(bound.RoleRef, binding.RoleRef) || !reflect.DeepEqual(bound.Subjects, binding.Subjects)) {
			return zero, zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, zero, cfg.ErrUnavailable
	}
	// ADR-190 decision 7: the owner, which serves the hub cluster's capacity
	// observation, mints the probe account's tokens and reads that account.
	tokens := &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name + "-token", Namespace: name}, Rules: []rbac.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, ResourceNames: []string{CapacityProbeAccount}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{CapacityProbeAccount}, Verbs: []string{"get"}}}}
	gotRole, err := api.RbacV1().Roles(name).Create(call, tokens, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if gotRole, err = api.RbacV1().Roles(name).Get(call, tokens.Name, meta.GetOptions{}); err == nil && !reflect.DeepEqual(gotRole.Rules, tokens.Rules) {
			return zero, zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, zero, cfg.ErrUnavailable
	}
	tokenBinding := &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name + "-token", Namespace: name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: tokens.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ownerNamespace, Name: owner}}}
	gotBinding, err := api.RbacV1().RoleBindings(name).Create(call, tokenBinding, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if gotBinding, err = api.RbacV1().RoleBindings(name).Get(call, tokenBinding.Name, meta.GetOptions{}); err == nil && (!reflect.DeepEqual(gotBinding.RoleRef, tokenBinding.RoleRef) || !reflect.DeepEqual(gotBinding.Subjects, tokenBinding.Subjects)) {
			return zero, zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, zero, cfg.ErrUnavailable
	}
	return contracts.WorkerObjectReference{Name: ns.Name, UID: string(ns.UID)}, contracts.WorkerObjectReference{Name: account.Name, UID: string(account.UID)}, nil
}

// CapacityProofs are live proofs of the three capacity guards (ADR-190):
// each probe's actual dry-run is denied by its own guard. The digests bind
// the capacity setup; the capacity guard is the setup's protection reader.
type CapacityProofs struct {
	Guard                       *CapacityGuard
	NamespaceDigest, Processing artifact.Digest
}

// ProveCapacitySources builds the three protections from the created
// sources and proves each once. workerProbe authenticates as the hub-worker
// account worker; selectorProbe as the dedicated capacity probe account.
func ProveCapacitySources(ctx context.Context, observer, workerProbe, selectorProbe *PermissionClient, s CapacitySources, control cfg.NamespaceRef, admins []cfg.KubernetesActor, worker contracts.WorkerObjectReference, keys []string) (CapacityProofs, error) {
	var out CapacityProofs
	pin := func(g contracts.OwnerDeploymentGuard) GuardPin {
		return GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}
	}
	guard, err := NewCapacityGuard(observer, workerProbe, cfg.CapacityAdministration{Name: s.Guard.Name, ControlNamespace: control, Administrators: admins, StatusUsers: []string{}, ProbeAccount: cfg.NamespaceRef{Name: worker.Name, UID: worker.UID}}, pin(s.Guard))
	if err != nil {
		return out, err
	}
	if _, err = guard.CapacityProtection(ctx); err != nil {
		return out, err
	}
	selectorRead, err := NewPermissionClientFrom(observer, cfg.NamespaceRef{Name: s.ProbeNamespace.Name, UID: s.ProbeNamespace.UID})
	if err != nil {
		return out, err
	}
	selector, err := NewCapacityNamespaceGuard(selectorRead, selectorProbe, cfg.CapacityNamespaceAdministration{Name: s.NamespaceGuard.Name, Administrators: admins, Keys: keys,
		ProbeNamespace: cfg.NamespaceRef{Name: s.ProbeNamespace.Name, UID: s.ProbeNamespace.UID}, ProbeAccount: cfg.NamespaceRef{Name: s.ProbeAccount.Name, UID: s.ProbeAccount.UID}}, pin(s.NamespaceGuard))
	if err != nil {
		return out, err
	}
	n, err := selector.CapacityNamespaceProtection(ctx)
	if err != nil {
		return out, err
	}
	processing, err := NewDownloadEnvironmentProtection(observer, workerProbe, cfg.ConfigMapAdministration{Name: s.ProcessingGuard.Name, SourceName: s.ProcessingSource.Name, ControlNamespace: control, Administrators: admins}, pin(s.ProcessingGuard))
	if err != nil {
		return out, err
	}
	digest, _, err := processing.current(ctx)
	if err != nil {
		return out, err
	}
	return CapacityProofs{Guard: guard, NamespaceDigest: n.Digest, Processing: digest}, nil
}

// ReadStoragePoolUID reads the operator-created EvidenceStoragePool's UID,
// which the capacity qualification binds as the system pool.
func ReadStoragePoolUID(ctx context.Context, config *rest.Config, namespace, name string) (string, error) {
	api, err := installerAPI(config)
	if err != nil || ctx == nil {
		return "", cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + namespace + "/evidencestoragepools/" + name).DoRaw(call)
	if err != nil {
		return "", cfg.ErrUnavailable
	}
	var pool struct {
		Metadata struct {
			Name, Namespace, UID string
			DeletionTimestamp    *meta.Time `json:"deletionTimestamp"`
		} `json:"metadata"`
	}
	if json.Unmarshal(raw, &pool) != nil || pool.Metadata.Name != name || pool.Metadata.Namespace != namespace || !authorization.UUID(pool.Metadata.UID) || pool.Metadata.DeletionTimestamp != nil {
		return "", cfg.ErrChanged
	}
	return pool.Metadata.UID, nil
}
