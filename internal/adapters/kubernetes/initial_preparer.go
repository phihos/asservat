package kubernetes

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
)

// InitialPreparer is an installation-only producer. A root receipt is public
// provenance, never a witness, cleanliness assertion, or recovery authority.
// The continuity bootstrap and its independent probe are operator-owned inputs.
type InitialPreparer struct {
	handoverConflicts map[string]initialHandoverConflict
	secretCompletions map[string]contracts.WorkerObjectReference
	providers         *contracts.InitialProviderProfile
	providerResponses map[string]contracts.InitialProviderResponse
	services          *contracts.InitialPreparationServices
	plan              contracts.InitialPreparationPlan
	rootUID           string
	creator           *InitialNamespaceCreator
	protection        *configMapProtection
	staging           GuardPin
	objects           []initialPreparationResource
	requestMu         sync.Mutex
	requestOwner      string
	requestClosed     bool
	requestJoin       sync.WaitGroup
	requestCancel     context.CancelFunc
	requestContext    context.Context
	requestProofs     map[string]contracts.InitialPreparationPodRequestCompletion
	probeResponses    map[string]contracts.InitialPreparationProbeResponse
}

func NewInitialPreparer(config *rest.Config, observer, probe *PermissionClient, c contracts.InitialPreparer) (*InitialPreparer, error) {
	if c.Format != contracts.InitialPreparerFormat || !validPreparerPlan(c.Plan) || c.RootUID != "" && !authorization.UUID(c.RootUID) || c.Continuity.Name != c.Plan.ContinuityName || !equalJSON(c.Continuity.Administrators, c.Plan.Administrators) {
		return nil, cfg.ErrInvalid
	}
	if c.Staging.Name != c.Plan.Workload.StagingGuard || !equalJSON(c.Staging.Administrators, c.Plan.Administrators) || !authorization.UUID(c.Staging.PolicyUID) || !authorization.UUID(c.Staging.BindingUID) || c.Staging.PolicyGeneration < 1 || !identity.Text(c.Staging.BindingResourceVersion, 128) {
		return nil, cfg.ErrInvalid
	}
	if observer == nil || observer.clusterID != c.Plan.ClusterID || probe == nil {
		return nil, cfg.ErrInvalid
	}
	p, b, e := InitialPreparationContinuityAdmission(c.Plan)
	if e != nil {
		return nil, e
	}
	plan := cfg.ConfigMapAdministration{Name: c.Plan.ContinuityName, SourceName: c.Plan.ProbeName, ControlNamespace: cfg.NamespaceRef{Name: c.Plan.BootstrapNamespace.Name, UID: c.Plan.BootstrapNamespace.UID}, Administrators: preparerAdministration(c.Plan).Administrators}
	pin := GuardPin{PolicyUID: c.Continuity.PolicyUID, PolicyGeneration: c.Continuity.PolicyGeneration, BindingUID: c.Continuity.BindingUID, BindingResourceVersion: c.Continuity.BindingResourceVersion}
	for _, id := range []string{pin.PolicyUID, pin.BindingUID} {
		if !authorization.UUID(id) {
			return nil, cfg.ErrInvalid
		}
	}
	g, e := newConfigMapProtection(observer, probe, plan, pin, "initial-preparation-continuity", initialContinuityDenial)
	if e != nil {
		return nil, e
	}
	normalizePermissionPolicy(&p.Spec)
	g.policy, g.binding = p.Spec, b.Spec
	creator, e := NewInitialNamespaceCreator(config, preparerAdministration(c.Plan), c.Plan.InstallationID, c.Plan.RequestID)
	if e != nil {
		return nil, e
	}
	// The effect client and independently checked observer must address the same API.
	if creator.api.Get().URL().String() != observer.api.Get().URL().String() || creator.api.Get().URL().String() != probe.api.Get().URL().String() {
		return nil, cfg.ErrInvalid
	}
	objects, e := preparerObjects(c.Plan)
	if e != nil {
		return nil, e
	}
	copyPlan := c.Plan
	if c.Plan.PrivateState != nil {
		v := *c.Plan.PrivateState
		copyPlan.PrivateState = &v
	}
	if c.Plan.HistoryManager != nil {
		v := *c.Plan.HistoryManager
		copyPlan.HistoryManager = &v
	}
	if c.Plan.HistoryProbe != nil {
		v := *c.Plan.HistoryProbe
		copyPlan.HistoryProbe = &v
	}
	copyPlan.Administrators = append([]contracts.OwnerDeploymentActor(nil), c.Plan.Administrators...)
	owner, e := prepUUID()
	if e != nil {
		return nil, e
	}
	requests, cancel := context.WithCancel(context.Background())
	result := &InitialPreparer{requestOwner: owner, requestContext: requests, requestCancel: cancel, plan: copyPlan, rootUID: c.RootUID, creator: creator, protection: g, objects: objects, staging: GuardPin{PolicyUID: c.Staging.PolicyUID, PolicyGeneration: c.Staging.PolicyGeneration, BindingUID: c.Staging.BindingUID, BindingResourceVersion: c.Staging.BindingResourceVersion}}
	if c.Plan.Handover != "" && (c.Services == nil || c.SQLMaterial == nil || c.Providers == nil) {
		cancel()
		return nil, cfg.ErrInvalid
	}
	if c.Services != nil {
		value, e := result.checkedServices(*c.Services)
		if e != nil {
			cancel()
			return nil, e
		}
		result.services = &value
	}
	if c.Providers != nil {
		if c.SQLMaterial == nil || c.Plan.PrivateState == nil || result.services == nil || !providerconfig.InitialProviderProfile(*c.Providers) || c.Providers.Material.Name == c.SQLMaterial.Name || c.Providers.Material.Name == c.Plan.PrivateState.Name {
			cancel()
			return nil, cfg.ErrInvalid
		}
		profile := *c.Providers
		result.providers = &profile
	}
	return result, nil
}

func (s *InitialPreparer) rootPath() string {
	return "/api/v1/namespaces/" + s.plan.BootstrapNamespace.Name + "/configmaps/" + s.plan.RootName
}
func (s *InitialPreparer) current(ctx context.Context) (time.Time, error) {
	if s == nil || ctx == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	start := s.protection.observer.now()
	ctx, cancel := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer cancel()
	if e := s.creator.administrator(ctx); e != nil {
		return time.Time{}, e
	}
	want := s.creator.policy.Spec.DeepCopy()
	normalizePermissionPolicy(want)
	if _, e := checkAdmissionGuard(ctx, s.creator, s.plan.Workload.StagingGuard, s.staging, *want, s.creator.binding.Spec); e != nil {
		return time.Time{}, e
	}
	_, until, e := s.protection.current(ctx)
	if e != nil {
		return time.Time{}, e
	}
	until = identity.Earlier(until, start.Add(5*time.Second))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if ctx.Err() != nil || !s.protection.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}
func (s *InitialPreparer) finish(ctx context.Context, until time.Time) error {
	if _, e := s.current(ctx); e != nil || ctx.Err() != nil || !s.protection.observer.now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}
func (s *InitialPreparer) decodeRoot(raw []byte) (*core.ConfigMap, contracts.InitialPreparationRoot, error) {
	var cm core.ConfigMap
	var zero contracts.InitialPreparationRoot
	if permissionJSON(raw, 96<<10, 8192) != nil || strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || !s.creator.owns(cm.ObjectMeta, s.plan.RootName) || cm.Namespace != s.plan.BootstrapNamespace.Name || len(cm.Annotations) != 2 || len(cm.Labels) != 0 || len(cm.Finalizers) != 0 || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.Immutable != nil && *cm.Immutable || s.rootUID != "" && string(cm.UID) != s.rootUID {
		return nil, zero, cfg.ErrChanged
	}
	w, e := contracts.DecodeInitialPreparationRoot(bytes.NewBufferString(cm.Data["root.json"]))
	if e != nil || w.Format != contracts.InitialPreparationRootFormat || w.InstallationID != s.plan.InstallationID || w.RequestID != s.plan.RequestID || w.PlanDigest != preparationPlanDigest(s.plan) || w.Creates == nil || len(w.Creates) > len(s.objects) || len(w.Creates) > contracts.InitialPreparationMaxCreates || w.RootUID != "" && w.RootUID != string(cm.UID) {
		return nil, zero, cfg.ErrChanged
	}
	if w.RootUID == "" && (len(w.Creates) != 0 || w.Phase != "declaring") {
		return nil, zero, cfg.ErrChanged
	}
	switch w.Phase {
	case "declaring":
	case "declared", "retiring", "retired":
		if len(w.Creates) != len(s.objects) {
			return nil, zero, cfg.ErrChanged
		}
	default:
		return nil, zero, cfg.ErrChanged
	}
	if !s.validActivation(w) || !s.validSchema(w) {
		return nil, zero, cfg.ErrChanged
	}
	seen := map[string]bool{}
	for i, v := range w.Creates {
		o := s.objects[i]
		m := preparerMetadata(o.object)
		if !authorization.UUID(v.OperationID) || seen[v.OperationID] || v.Kind != o.object.GetObjectKind().GroupVersionKind().Kind || v.Name != m.Name || v.SpecDigest != o.digest || !validPreparerReceipt(v.Receipt) || v.Receipt == nil && (i != len(w.Creates)-1 || w.Phase != "declaring") {
			return nil, zero, cfg.ErrChanged
		}
		seen[v.OperationID] = true
	}
	return &cm, w, nil
}
func (s *InitialPreparer) read(ctx context.Context) (*core.ConfigMap, contracts.InitialPreparationRoot, error) {
	b, e := s.creator.raw(ctx, s.rootPath(), nil)
	if e != nil {
		return nil, contracts.InitialPreparationRoot{}, e
	}
	return s.decodeRoot(b)
}
func (s *InitialPreparer) write(ctx context.Context, cm *core.ConfigMap, w contracts.InitialPreparationRoot, until time.Time) error {
	b, e := json.Marshal(w)
	if e != nil || len(b) > contracts.InitialPreparationMaxBytes {
		return cfg.ErrInvalid
	}
	cm = cm.DeepCopy()
	cm.Data = map[string]string{"root.json": string(b)}
	b, e = json.Marshal(cm)
	if e != nil {
		return cfg.ErrInvalid
	}
	raw, e := s.creator.api.Put().AbsPath(s.rootPath()).Param("fieldValidation", "Strict").MaxRetries(0).Body(b).DoRaw(ctx)
	if e != nil {
		return cfg.ErrUnavailable
	}
	_, got, e := s.decodeRoot(raw)
	if e != nil || !equalJSON(got, w) {
		return cfg.ErrChanged
	}
	return s.finish(ctx, until)
}

// Open resumes one root under its unchanged policy/binding pins. A missing
// externally retained UID never becomes a new root. Initial same-name CREATE
// may be repeated only because DELETE and replacement are denied continuously.
func (s *InitialPreparer) Open(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	cm, w, e := s.read(ctx)
	if apierrors.IsNotFound(e) && s.rootUID == "" {
		want, err := BuildInitialPreparationRoot(s.plan)
		if err != nil {
			return zero, err
		}
		_, err = s.creator.post(ctx, "/api/v1/namespaces/"+s.plan.BootstrapNamespace.Name+"/configmaps", want)
		if errors.Is(err, cfg.ErrDenied) {
			return zero, err
		}
		cm, w, e = s.read(ctx)
	}
	if e != nil {
		if errors.Is(e, cfg.ErrChanged) || errors.Is(e, cfg.ErrInvalid) || apierrors.IsNotFound(e) && s.rootUID != "" {
			return zero, cfg.ErrChanged
		}
		return zero, cfg.ErrUnavailable
	}
	if w.RootUID == "" {
		w.RootUID = string(cm.UID)
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	return w, nil
}

func prepUUID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", cfg.ErrUnavailable
	}
	b[6], b[8] = b[6]&15|64, b[8]&63|128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (s *InitialPreparer) verified(raw []byte, o initialPreparationResource, intent contracts.InitialPreparationCreate, retired bool) (runtime.Object, contracts.InitialPreparationReceipt, error) {
	var zero contracts.InitialPreparationReceipt
	v := o.object.DeepCopyObject()
	switch v.(type) {
	case *core.Namespace:
		v = new(core.Namespace)
	case *core.ServiceAccount:
		v = new(core.ServiceAccount)
	case *rbac.Role:
		v = new(rbac.Role)
	case *rbac.RoleBinding:
		v = new(rbac.RoleBinding)
	case *rbac.ClusterRole:
		v = new(rbac.ClusterRole)
	case *rbac.ClusterRoleBinding:
		v = new(rbac.ClusterRoleBinding)
	case *admission.ValidatingAdmissionPolicy:
		v = new(admission.ValidatingAdmissionPolicy)
	case *admission.ValidatingAdmissionPolicyBinding:
		v = new(admission.ValidatingAdmissionPolicyBinding)
	default:
		return nil, zero, cfg.ErrInvalid
	}
	if permissionJSON(raw, 64<<10, 16384) != nil || strictGuardJSON(raw, v) != nil {
		return nil, zero, cfg.ErrChanged
	}
	m := preparerMetadata(v)
	if !s.creator.owns(*m, intent.Name) || m.Namespace != o.namespace || len(m.Annotations) != 3 || m.Annotations[initialPreparationOperationAnnotation] != intent.OperationID || len(m.OwnerReferences) != 0 || len(m.Finalizers) != 0 || intent.Receipt != nil && intent.Receipt.UID != string(m.UID) {
		return nil, zero, cfg.ErrChanged
	}
	receipt := contracts.InitialPreparationReceipt{UID: string(m.UID), ResourceVersion: m.ResourceVersion}
	want := o.object.DeepCopyObject()
	compare := v.DeepCopyObject()
	cm := preparerMetadata(compare)
	labels := cm.Labels
	*cm = meta.ObjectMeta{Name: intent.Name, Namespace: o.namespace}
	switch x := compare.(type) {
	case *core.Namespace:
		if len(labels) != 2 || labels["kubernetes.io/metadata.name"] != intent.Name || labels["pod-security.kubernetes.io/enforce"] != "restricted" || len(x.Spec.Finalizers) != 1 || x.Spec.Finalizers[0] != core.FinalizerKubernetes || x.Status.Phase != core.NamespaceActive {
			return nil, zero, cfg.ErrChanged
		}
		x.Labels = map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}
		x.Spec = core.NamespaceSpec{}
		x.Status = core.NamespaceStatus{}
	case *admission.ValidatingAdmissionPolicy:
		normalizePermissionPolicy(&x.Spec)
		normalizePermissionPolicy(&want.(*admission.ValidatingAdmissionPolicy).Spec)
		x.Status = admission.ValidatingAdmissionPolicyStatus{}
	default:
		if len(labels) != 0 {
			return nil, zero, cfg.ErrChanged
		}
	}
	if retired {
		if !preparationAuthorityEmpty(compare) {
			return nil, zero, cfg.ErrChanged
		}
		retirePreparationAuthority(want)
		retirePreparationAuthority(compare)
	}
	if !equalJSON(compare, want) {
		return nil, zero, cfg.ErrChanged
	}
	return v, receipt, nil
}

// EnsureNext admits exactly the next compiled declarative intent. Its replay
// can repeat only that identical named CREATE, never a different spec or UID.
// One pending journal entry remains counted through all ambiguous replies.
func (s *InitialPreparer) EnsureNext(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	cm, w, e := s.read(ctx)
	if e != nil {
		if errors.Is(e, cfg.ErrChanged) || errors.Is(e, cfg.ErrInvalid) || apierrors.IsNotFound(e) && s.rootUID != "" {
			return zero, cfg.ErrChanged
		}
		return zero, cfg.ErrUnavailable
	}
	if w.RootUID == "" || w.Phase != "declaring" || s.plan.SchemaInitialization != "" && (w.Schema == nil || w.Schema.CompletedAt == nil) {
		return zero, cfg.ErrChanged
	}
	i := len(w.Creates)
	if i > 0 && w.Creates[i-1].Receipt == nil {
		i--
	}
	if i == len(s.objects) {
		w.Phase = "declared"
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
		return w, nil
	}
	o := s.objects[i]
	if i == len(w.Creates) {
		id, err := prepUUID()
		if err != nil {
			return zero, err
		}
		w.Creates = append(w.Creates, contracts.InitialPreparationCreate{OperationID: id, Kind: o.object.GetObjectKind().GroupVersionKind().Kind, Name: preparerMetadata(o.object).Name, SpecDigest: o.digest})
		if e = s.write(ctx, cm, w, until); e != nil {
			return zero, e
		}
		cm, w, e = s.read(ctx)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
	}
	intent := w.Creates[i]
	path := o.path + "/" + intent.Name
	raw, e := s.creator.raw(ctx, path, nil)
	if apierrors.IsNotFound(e) && intent.Receipt == nil {
		v := o.object.DeepCopyObject()
		m := preparerMetadata(v)
		s.creator.stamp(m)
		m.Annotations[initialPreparationOperationAnnotation] = intent.OperationID
		_, err := s.creator.post(ctx, o.path, v)
		if errors.Is(err, cfg.ErrDenied) {
			return zero, err
		}
		raw, e = s.creator.raw(ctx, path, nil)
	}
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	_, receipt, e := s.verified(raw, o, intent, false)
	if e != nil {
		return zero, e
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	if intent.Receipt != nil {
		return w, nil
	} // A concurrent observer already pinned the original receipt.
	w.Creates[i].Receipt = &receipt
	if e = s.write(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}

// Declare runs a bounded finite inventory, not a watch or a retry engine. A
// restarted command resumes the original root; ordinary uncertainty is reported
// without changing its plan, operation IDs, retained UIDs or authority periods.
func (s *InitialPreparer) Declare(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	w, e := s.Open(ctx)
	if e != nil {
		return w, e
	}
	for n := 0; n <= len(s.objects); n++ {
		if w.Phase == "declared" {
			return s.VerifyDeclared(ctx)
		}
		if w.Phase != "declaring" {
			return w, cfg.ErrChanged
		}
		w, e = s.EnsureNext(ctx)
		if e != nil {
			return w, e
		}
	}
	if w.Phase == "declared" {
		return s.VerifyDeclared(ctx)
	}
	return w, cfg.ErrUnavailable
}
func (s *InitialPreparer) VerifyDeclared(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	_, w, e := s.read(ctx)
	if e != nil || w.Phase != "declared" {
		return zero, cfg.ErrChanged
	}
	for i, o := range s.objects {
		v, e := s.creator.raw(ctx, o.path+"/"+w.Creates[i].Name, nil)
		if e != nil {
			return zero, cfg.ErrUnavailable
		}
		if _, _, e = s.verified(v, o, w.Creates[i], false); e != nil {
			return zero, e
		}
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	return w, nil
}

// Roles and bindings lose authority in-place. Names and UIDs remain occupied so
// a delayed original POST cannot restore the old rules or subjects.
func retirePreparationAuthority(v runtime.Object) bool {
	switch v := v.(type) {
	case *rbac.Role:
		v.Rules = []rbac.PolicyRule{}
	case *rbac.ClusterRole:
		v.Rules = []rbac.PolicyRule{}
	case *rbac.RoleBinding:
		v.Subjects = nil
	case *rbac.ClusterRoleBinding:
		v.Subjects = nil
	default:
		return false
	}
	return true
}

func preparationAuthorityEmpty(v runtime.Object) bool {
	switch v := v.(type) {
	case *rbac.Role:
		return len(v.Rules) == 0
	case *rbac.ClusterRole:
		return len(v.Rules) == 0
	case *rbac.RoleBinding:
		return len(v.Subjects) == 0
	case *rbac.ClusterRoleBinding:
		return len(v.Subjects) == 0
	}
	return false
}

// RetireSetupAuthority removes only these bootstrap RBAC rules/subjects. It
// neither infers activation success nor deletes/reuses any identity. Caller
// composition decides when retirement is appropriate; current administration
// is mandatory even after an earlier run was interrupted.
func (s *InitialPreparer) RetireSetupAuthority(ctx context.Context) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	step, cancel := context.WithDeadline(ctx, until)
	cm, w, e := s.read(step)
	if e != nil {
		cancel()
		return zero, cfg.ErrUnavailable
	}
	if w.Phase == "declared" {
		w.Phase = "retiring"
		e = s.write(step, cm, w, until)
	} else if w.Phase != "retiring" && w.Phase != "retired" {
		e = cfg.ErrChanged
	}
	cancel()
	if e != nil {
		return zero, e
	}
	for i, o := range s.objects {
		if !retirePreparationAuthority(o.object.DeepCopyObject()) {
			continue
		}
		if e = s.retireOne(ctx, i); e != nil {
			return zero, e
		}
	}
	until, e = s.current(ctx)
	if e != nil {
		return zero, e
	}
	step, cancel = context.WithDeadline(ctx, until)
	defer cancel()
	cm, w, e = s.read(step)
	if e != nil || w.Phase != "retiring" && w.Phase != "retired" {
		return zero, cfg.ErrChanged
	}
	if w.Phase == "retiring" {
		w.Phase = "retired"
		if e = s.write(step, cm, w, until); e != nil {
			return zero, e
		}
	}
	if e = s.finish(step, until); e != nil {
		return zero, e
	}
	return w, nil
}
func (s *InitialPreparer) retireOne(ctx context.Context, i int) error {
	until, e := s.current(ctx)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	_, w, e := s.read(ctx)
	if e != nil || w.Phase != "retiring" && w.Phase != "retired" {
		return cfg.ErrChanged
	}
	o := s.objects[i]
	intent := w.Creates[i]
	path := o.path + "/" + intent.Name
	raw, e := s.creator.raw(ctx, path, nil)
	if e != nil {
		return cfg.ErrUnavailable
	}
	v, _, e := s.verified(raw, o, intent, false)
	if e != nil {
		if _, _, e = s.verified(raw, o, intent, true); e != nil {
			return e
		}
		return s.finish(ctx, until)
	}
	if w.Phase == "retired" {
		return cfg.ErrChanged
	}
	if !retirePreparationAuthority(v) {
		return cfg.ErrInvalid
	}
	raw, e = json.Marshal(v)
	if e != nil {
		return cfg.ErrInvalid
	}
	if _, e = s.creator.api.Put().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).DoRaw(ctx); e != nil {
		return cfg.ErrUnavailable
	}
	raw, e = s.creator.raw(ctx, path, nil)
	if e != nil {
		return cfg.ErrUnavailable
	}
	if _, _, e = s.verified(raw, o, intent, true); e != nil {
		return e
	}
	return s.finish(ctx, until)
}
