package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	scheduling "k8s.io/api/scheduling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// DownloadWorkerSources are the hub-cluster download worker objects the
// continuation creates before the permission step (ADR-204 decision 1): the
// restricted worker namespace, the worker account, the zero-priority
// non-preempting class, the still-empty store Secret and the guarded worker
// profile source (ADR-070). Their references feed the hub-worker's worker
// configuration section and, after promotion, the profile itself.
type DownloadWorkerSources struct {
	Namespace, ServiceAccount, PriorityClass, StoreCredentials contracts.WorkerObjectReference
	Profile                                                    contracts.OwnerPublicGuardedSource
}

// DownloadWorkerRBAC is the named access of the two hub accounts that read
// the worker namespace; none of it exists in the original resource journal.
type DownloadWorkerRBAC struct {
	Roles           []*rbac.Role
	Bindings        []*rbac.RoleBinding
	ClusterRoles    []*rbac.ClusterRole
	ClusterBindings []*rbac.ClusterRoleBinding
}

const downloadWorkerStoreFile = "credentials.json"

// BuildDownloadWorkerNamespace is the workers' own namespace with Pod Security
// restricted enforced; the dispatcher refuses any other enforcement.
func BuildDownloadWorkerNamespace(installation string) *core.Namespace {
	return &core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: contracts.DownloadWorkerNamespaceName(installation), Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}
}

// BuildDownloadWorkerPriorityClass is ADR-069's exact class: value zero, not
// the cluster default, never preempting.
func BuildDownloadWorkerPriorityClass(installation string) *scheduling.PriorityClass {
	return &scheduling.PriorityClass{TypeMeta: meta.TypeMeta{APIVersion: "scheduling.k8s.io/v1", Kind: "PriorityClass"}, ObjectMeta: meta.ObjectMeta{Name: contracts.DownloadWorkerPriorityClassName(installation)},
		Value: 0, GlobalDefault: false, PreemptionPolicy: ptr.To(core.PreemptNever), Description: "Asservat download workers: zero priority, never preempting."}
}

// BuildDownloadWorkerRBAC grants the two hub accounts exactly the named reads
// their readers perform in the worker namespace (ADR-204 decisions 1 and 2):
//   - the hub-api account dispatches and attests workers (Jobs create, get and
//     delete; Pods get and list; the worker account, control ConfigMap and
//     store Secret by name; the PriorityClass; TokenReviews) and reads the
//     guarded profile source, proving its guard with a dry-run UPDATE;
//   - the hub-worker account reads the profile source and the store Secret it
//     checks, with the same dry-run UPDATE probe on the source only.
//
// Both get only the worker namespace itself and the profile guard
// cluster-wide. Job names are per dispatch, so Jobs cannot be named.
func BuildDownloadWorkerRBAC(installation, hubNamespace, owner, hubWorker string) (DownloadWorkerRBAC, error) {
	var out DownloadWorkerRBAC
	if !authorization.UUID(installation) || len(validation.IsDNS1123Label(hubNamespace)) != 0 || hubNamespace == contracts.DownloadWorkerNamespaceName(installation) || len(validation.IsDNS1123Subdomain(owner)) != 0 || len(validation.IsDNS1123Subdomain(hubWorker)) != 0 || owner == hubWorker {
		return out, cfg.ErrInvalid
	}
	ns := contracts.DownloadWorkerNamespaceName(installation)
	source, control, store := contracts.DownloadWorkerProfileName(installation), contracts.DownloadWorkerControlName(installation), contracts.DownloadWorkerStoreName(installation)
	guard := contracts.DownloadWorkerProfileGuardName(installation)
	roles := []struct {
		suffix, account string
		rules           []rbac.PolicyRule
		cluster         []rbac.PolicyRule
	}{
		{"-owner", owner, []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{source, control}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{source}, Verbs: []string{"update"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{store}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{contracts.DownloadWorkerAccountName(installation)}, Verbs: []string{"get"}},
			{APIGroups: []string{"batch"}, Resources: []string{"jobs"}, Verbs: []string{"create", "get", "delete"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		}, []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get"}},
			{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{guard}, Verbs: []string{"get"}},
			{APIGroups: []string{"scheduling.k8s.io"}, Resources: []string{"priorityclasses"}, ResourceNames: []string{contracts.DownloadWorkerPriorityClassName(installation)}, Verbs: []string{"get"}},
			{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"tokenreviews"}, Verbs: []string{"create"}},
		}},
		{"-hub-worker", hubWorker, []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{source}, Verbs: []string{"get", "update"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{store}, Verbs: []string{"get"}},
		}, []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns}, Verbs: []string{"get"}},
			{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{guard}, Verbs: []string{"get"}},
		}},
	}
	for _, r := range roles {
		name, clusterName := ns+r.suffix, "asservat."+ns+r.suffix
		subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: r.account, Namespace: hubNamespace}}
		out.Roles = append(out.Roles, &rbac.Role{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "Role"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Rules: r.rules})
		out.Bindings = append(out.Bindings, &rbac.RoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "RoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: ns}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}})
		out.ClusterRoles = append(out.ClusterRoles, &rbac.ClusterRole{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRole"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Rules: r.cluster})
		out.ClusterBindings = append(out.ClusterBindings, &rbac.ClusterRoleBinding{TypeMeta: meta.TypeMeta{APIVersion: rbac.SchemeGroupVersion.String(), Kind: "ClusterRoleBinding"}, ObjectMeta: meta.ObjectMeta{Name: clusterName}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: clusterName}})
	}
	return out, nil
}

// EnsureDownloadWorkerSources creates or reopens the worker objects. Existing
// objects must match exactly; an existing profile source is kept as the
// administrator left it, and an existing store Secret only while empty or
// filled once (FillDownloadWorkerStore). Nothing existing is updated.
func EnsureDownloadWorkerSources(ctx context.Context, config *rest.Config, installation string, hub cfg.NamespaceRef, admins []cfg.KubernetesActor, owner, hubWorker contracts.WorkerObjectReference) (DownloadWorkerSources, error) {
	var out DownloadWorkerSources
	if ctx == nil || config == nil || !authorization.UUID(installation) || hub.Name == "" || !authorization.UUID(hub.UID) || len(admins) == 0 || !installationRefValid(owner.Name, owner.UID) || !installationRefValid(hubWorker.Name, hubWorker.UID) {
		return out, cfg.ErrInvalid
	}
	access, err := BuildDownloadWorkerRBAC(installation, hub.Name, owner.Name, hubWorker.Name)
	if err != nil {
		return out, err
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	want := BuildDownloadWorkerNamespace(installation)
	ns, err := api.CoreV1().Namespaces().Create(call, want, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		ns, err = api.CoreV1().Namespaces().Get(call, want.Name, meta.GetOptions{})
	}
	if err != nil || !authorization.UUID(string(ns.UID)) {
		return out, cfg.ErrUnavailable
	}
	if ns.DeletionTimestamp != nil || ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		return out, cfg.ErrChanged
	}
	out.Namespace = contracts.WorkerObjectReference{Name: ns.Name, UID: string(ns.UID)}
	name := contracts.DownloadWorkerAccountName(installation)
	accounts := api.CoreV1().ServiceAccounts(ns.Name)
	a, err := accounts.Create(call, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if a, err = accounts.Get(call, name, meta.GetOptions{}); err == nil && (a.AutomountServiceAccountToken == nil || *a.AutomountServiceAccountToken || a.DeletionTimestamp != nil) {
			return DownloadWorkerSources{}, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(a.UID)) {
		return DownloadWorkerSources{}, cfg.ErrUnavailable
	}
	out.ServiceAccount = contracts.WorkerObjectReference{Name: a.Name, UID: string(a.UID)}
	class := BuildDownloadWorkerPriorityClass(installation)
	pc, err := api.SchedulingV1().PriorityClasses().Create(call, class, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if pc, err = api.SchedulingV1().PriorityClasses().Get(call, class.Name, meta.GetOptions{}); err == nil && (pc.Value != 0 || pc.GlobalDefault || pc.PreemptionPolicy == nil || *pc.PreemptionPolicy != core.PreemptNever || pc.DeletionTimestamp != nil) {
			return DownloadWorkerSources{}, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(pc.UID)) {
		return DownloadWorkerSources{}, cfg.ErrUnavailable
	}
	out.PriorityClass = contracts.WorkerObjectReference{Name: pc.Name, UID: string(pc.UID)}
	secrets := api.CoreV1().Secrets(ns.Name)
	storeName := contracts.DownloadWorkerStoreName(installation)
	store, err := secrets.Create(call, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: storeName}, Type: core.SecretTypeOpaque}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if store, err = secrets.Get(call, storeName, meta.GetOptions{}); err == nil && !downloadWorkerStoreReusable(store) {
			return DownloadWorkerSources{}, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(store.UID)) {
		return DownloadWorkerSources{}, cfg.ErrUnavailable
	}
	out.StoreCredentials = contracts.WorkerObjectReference{Name: store.Name, UID: string(store.UID)}
	configMaps := api.CoreV1().ConfigMaps(ns.Name)
	sourceName := contracts.DownloadWorkerProfileName(installation)
	source, err := configMaps.Create(call, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: sourceName}, Data: map[string]string{"worker-profile.json": contracts.UnconfiguredWorkerConfiguration(installation)}}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		source, err = configMaps.Get(call, sourceName, meta.GetOptions{})
	}
	if err != nil || !authorization.UUID(string(source.UID)) || len(source.Data) != 1 || source.Data["worker-profile.json"] == "" || source.DeletionTimestamp != nil {
		return DownloadWorkerSources{}, cfg.ErrUnavailable
	}
	policy, binding, err := WorkerConfigurationAdmission(cfg.WorkerAdministration{Name: contracts.DownloadWorkerProfileGuardName(installation), SourceName: sourceName, ControlNamespace: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, Administrators: admins})
	if err != nil {
		return DownloadWorkerSources{}, err
	}
	guard, err := ensureAdmissionGuard(call, api, policy, binding, admins)
	if err != nil {
		return DownloadWorkerSources{}, err
	}
	out.Profile = contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: source.Name, UID: string(source.UID)}, Guard: guard}
	if err = ensureDownloadWorkerRBAC(call, api, access); err != nil {
		return DownloadWorkerSources{}, err
	}
	return out, nil
}

// downloadWorkerStoreReusable accepts the store Secret this step created,
// either still empty or filled once and immutable.
func downloadWorkerStoreReusable(s *core.Secret) bool {
	if s.Type != core.SecretTypeOpaque || s.DeletionTimestamp != nil || len(s.StringData) != 0 {
		return false
	}
	if s.Immutable != nil && *s.Immutable {
		return len(s.Data) == 1 && len(s.Data[downloadWorkerStoreFile]) != 0
	}
	return len(s.Data) == 0
}

func ensureDownloadWorkerRBAC(call context.Context, api kubernetes.Interface, w DownloadWorkerRBAC) error {
	for _, r := range w.Roles {
		got, e := api.RbacV1().Roles(r.Namespace).Create(call, r, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			if got, e = api.RbacV1().Roles(r.Namespace).Get(call, r.Name, meta.GetOptions{}); e == nil && !reflect.DeepEqual(got.Rules, r.Rules) {
				return cfg.ErrChanged
			}
		}
		if e != nil {
			return cfg.ErrUnavailable
		}
	}
	for _, b := range w.Bindings {
		got, e := api.RbacV1().RoleBindings(b.Namespace).Create(call, b, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			if got, e = api.RbacV1().RoleBindings(b.Namespace).Get(call, b.Name, meta.GetOptions{}); e == nil && (!reflect.DeepEqual(got.Subjects, b.Subjects) || got.RoleRef != b.RoleRef) {
				return cfg.ErrChanged
			}
		}
		if e != nil {
			return cfg.ErrUnavailable
		}
	}
	for _, r := range w.ClusterRoles {
		got, e := api.RbacV1().ClusterRoles().Create(call, r, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			if got, e = api.RbacV1().ClusterRoles().Get(call, r.Name, meta.GetOptions{}); e == nil && (!reflect.DeepEqual(got.Rules, r.Rules) || got.AggregationRule != nil) {
				return cfg.ErrChanged
			}
		}
		if e != nil {
			return cfg.ErrUnavailable
		}
	}
	for _, b := range w.ClusterBindings {
		got, e := api.RbacV1().ClusterRoleBindings().Create(call, b, meta.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			if got, e = api.RbacV1().ClusterRoleBindings().Get(call, b.Name, meta.GetOptions{}); e == nil && (!reflect.DeepEqual(got.Subjects, b.Subjects) || got.RoleRef != b.RoleRef) {
				return cfg.ErrChanged
			}
		}
		if e != nil {
			return cfg.ErrUnavailable
		}
	}
	return nil
}

// FillDownloadWorkerStore writes the worker store credential (ADR-204
// decision 5) into the exact empty store Secret and makes it immutable, as
// the profile reader requires. A rerun accepts only the same content.
func FillDownloadWorkerStore(ctx context.Context, config *rest.Config, s DownloadWorkerSources, credentials []byte) error {
	if ctx == nil || config == nil || !installationRefValid(s.Namespace.Name, s.Namespace.UID) || !authorization.UUID(s.StoreCredentials.UID) || len(credentials) == 0 || len(credentials) > contracts.WorkerStoreCredentialsMaxBytes {
		return cfg.ErrInvalid
	}
	if c, e := contracts.DecodeWorkerStoreCredentials(bytes.NewReader(credentials)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken != "" && c.ExpiresAt == "" {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := api.CoreV1().Secrets(s.Namespace.Name)
	current, err := secrets.Get(call, s.StoreCredentials.Name, meta.GetOptions{})
	if err != nil || string(current.UID) != s.StoreCredentials.UID {
		return cfg.ErrUnavailable
	}
	if !downloadWorkerStoreReusable(current) {
		return cfg.ErrChanged
	}
	if current.Immutable != nil && *current.Immutable {
		if bytes.Equal(current.Data[downloadWorkerStoreFile], credentials) {
			return nil
		}
		return cfg.ErrChanged
	}
	current.Data, current.Immutable = map[string][]byte{downloadWorkerStoreFile: credentials}, ptr.To(true)
	updated, err := secrets.Update(call, current, meta.UpdateOptions{})
	if err != nil || string(updated.UID) != s.StoreCredentials.UID || updated.Immutable == nil || !*updated.Immutable {
		return cfg.ErrUnavailable
	}
	return nil
}

// EnsureDownloadWorkerControl creates the immutable worker.json control
// ConfigMap (ADR-069), or reopens it when its data is byte-identical, and
// returns the reference the profile pins: name, UID and the exact data digest.
func EnsureDownloadWorkerControl(ctx context.Context, config *rest.Config, installation string, namespace contracts.WorkerObjectReference, raw []byte) (contracts.LocalKeySecretReference, error) {
	var out contracts.LocalKeySecretReference
	data := map[string]string{"worker.json": string(raw)}
	digest, err := WorkerControlDigest(data)
	if ctx == nil || config == nil || !authorization.UUID(installation) || namespace.Name != contracts.DownloadWorkerNamespaceName(installation) || !authorization.UUID(namespace.UID) || err != nil {
		return out, cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	name := contracts.DownloadWorkerControlName(installation)
	configMaps := api.CoreV1().ConfigMaps(namespace.Name)
	c, err := configMaps.Create(call, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Data: data}, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if c, err = configMaps.Get(call, name, meta.GetOptions{}); err == nil && (c.Immutable == nil || !*c.Immutable || len(c.BinaryData) != 0 || !reflect.DeepEqual(c.Data, data) || c.DeletionTimestamp != nil) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(c.UID)) {
		return out, cfg.ErrUnavailable
	}
	return contracts.LocalKeySecretReference{Name: c.Name, UID: string(c.UID), SHA256: hex.EncodeToString(digest[:])}, nil
}

// ConfigureDownloadWorkerProfile replaces the unconfigured marker in the
// exact guarded profile source with profile, as an administrator: the guard
// admits only administrators, and the hub-worker accepts and audits the new
// revision before any reader uses it (ADR-070). A rerun accepts the same
// document; any other administrator content is a change, never overwritten.
func ConfigureDownloadWorkerProfile(ctx context.Context, config *rest.Config, installation string, s DownloadWorkerSources, profile []byte) error {
	if ctx == nil || config == nil || !authorization.UUID(installation) || !installationRefValid(s.Namespace.Name, s.Namespace.UID) || !installationRefValid(s.Profile.Source.Name, s.Profile.Source.UID) || len(profile) == 0 || len(profile) > 16384 {
		return cfg.ErrInvalid
	}
	api, err := installerAPI(config)
	if err != nil {
		return cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	configMaps := api.CoreV1().ConfigMaps(s.Namespace.Name)
	current, err := configMaps.Get(call, s.Profile.Source.Name, meta.GetOptions{})
	if err != nil || string(current.UID) != s.Profile.Source.UID {
		return cfg.ErrUnavailable
	}
	if current.DeletionTimestamp != nil || len(current.Data) != 1 || len(current.BinaryData) != 0 {
		return cfg.ErrChanged
	}
	switch current.Data["worker-profile.json"] {
	case string(profile):
		return nil
	case contracts.UnconfiguredWorkerConfiguration(installation):
	default:
		return cfg.ErrChanged
	}
	current.Data = map[string]string{"worker-profile.json": string(profile)}
	updated, err := configMaps.Update(call, current, meta.UpdateOptions{})
	if err != nil || string(updated.UID) != s.Profile.Source.UID || updated.Data["worker-profile.json"] != string(profile) {
		return cfg.ErrUnavailable
	}
	return nil
}
