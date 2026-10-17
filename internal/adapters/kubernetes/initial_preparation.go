package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// The public preparation probe doubles as the bounded durable creation journal.
// It records intent/provenance, never authority or proof of clean setup history.
func (s *InitialNamespaceCreator) preparation(refs InitialNamespaceResources, plan artifact.Digest) contracts.InitialPreparation {
	g := contracts.OwnerDeploymentGuard{Name: s.plan.Name, PolicyUID: refs.Guard.PolicyUID, PolicyGeneration: refs.Guard.PolicyGeneration, BindingUID: refs.Guard.BindingUID, BindingResourceVersion: refs.Guard.BindingResourceVersion}
	for _, a := range s.plan.Administrators {
		g.Administrators = append(g.Administrators, contracts.OwnerDeploymentActor{Kind: a.Kind, Name: a.Name})
	}
	return contracts.InitialPreparation{Format: contracts.InitialPreparationFormat, InstallationID: s.installation, RequestID: s.request, PlanDigest: hex.EncodeToString(plan[:]), Namespace: contracts.WorkerObjectReference{Name: refs.Namespace.Name, UID: refs.Namespace.UID}, Guard: g, Creates: []contracts.InitialPreparationCreate{}}
}

// CreateJournal persists the initial acknowledged namespace/guard identities
// before future installer identities or credentials. It creates only the public
// marker: the independently authenticated probe must still be provisioned and
// prove actual enforcement before this journal admits subsequent operations.
// The caller retains the returned UID; an unknown reply never creates again or
// adopts an existing journal. Partial namespace creation needs separate repair.
func (s *InitialNamespaceCreator) CreateJournal(ctx context.Context, refs InitialNamespaceResources, plan artifact.Digest) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	if s == nil || ctx == nil || plan == (artifact.Digest{}) {
		return zero, cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if err := s.Resume(ctx, refs); err != nil {
		return zero, err
	}
	want := s.preparation(refs, plan)
	b, err := json.Marshal(want)
	if err != nil {
		return zero, cfg.ErrInvalid
	}
	cm := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.ProbeSource, Namespace: s.plan.Namespace}, Data: map[string]string{"preparation.json": string(b)}}
	s.stamp(&cm.ObjectMeta)
	raw, err := s.post(ctx, "/api/v1/namespaces/"+s.plan.Namespace+"/configmaps", cm)
	if err != nil {
		return zero, err
	}
	cm = core.ConfigMap{}
	if strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Namespace != s.plan.Namespace || !s.owns(cm.ObjectMeta, s.plan.ProbeSource) || cm.Immutable != nil && *cm.Immutable || len(cm.BinaryData) != 0 || len(cm.Data) != 1 || cm.Data["preparation.json"] != string(b) {
		return zero, cfg.ErrChanged
	}
	ref := contracts.WorkerObjectReference{Name: cm.Name, UID: string(cm.UID)}
	if err := s.Resume(ctx, refs); err != nil || ctx.Err() != nil {
		// This acknowledges only object creation, not usable current state.
		return ref, cfg.ErrUnavailable
	}
	return ref, nil
}

type InitialPreparationJournal struct {
	creator    *InitialNamespaceCreator
	protection *InitialNamespaceProtection
	ref        contracts.WorkerObjectReference
	expected   contracts.InitialPreparation
}

// A fresh Begin acknowledgement reserves one execution attempt in this journal.
// It is not an execution permit: the supervisor must independently check the
// target/operation and current protection before any actual resource mutation.
type InitialPreparationStart struct {
	Fresh bool
	State contracts.InitialPreparation
}

func NewInitialPreparationJournal(creator *InitialNamespaceCreator, protection *InitialNamespaceProtection, refs InitialNamespaceResources, ref contracts.WorkerObjectReference, plan artifact.Digest) (*InitialPreparationJournal, error) {
	if creator == nil || protection == nil || protection.guard == nil || ref.Name != creator.plan.ProbeSource || !authorization.UUID(ref.UID) || !authorization.UUID(refs.Guard.PolicyUID) || !authorization.UUID(refs.Guard.BindingUID) || plan == (artifact.Digest{}) || protection.guard.observer.control != refs.Namespace || protection.guard.pin != refs.Guard || protection.guard.plan.SourceName != ref.Name {
		return nil, cfg.ErrInvalid
	}
	if creator.api.Get().URL().String() != protection.guard.observer.api.Get().URL().String() {
		return nil, cfg.ErrInvalid
	}
	want := creator.policy.Spec.DeepCopy()
	normalizePermissionPolicy(want)
	if !equalJSON(protection.guard.policy, *want) || !equalJSON(protection.guard.binding, creator.binding.Spec) {
		return nil, cfg.ErrInvalid
	}
	return &InitialPreparationJournal{creator, protection, ref, creator.preparation(refs, plan)}, nil
}

func initialPreparationCreateValid(v contracts.InitialPreparationCreate) bool {
	if !authorization.UUID(v.OperationID) || len(validation.IsDNS1123Subdomain(v.Name)) != 0 || len(v.SpecDigest) != 64 {
		return false
	}
	b, err := hex.DecodeString(v.SpecDigest)
	if err != nil || hex.EncodeToString(b) != v.SpecDigest || bytes.Equal(b, make([]byte, 32)) {
		return false
	}
	switch v.Kind {
	case "ServiceAccount", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "ConfigMap", "Secret", "Pod", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding":
	default:
		return false
	}
	return v.Receipt == nil || authorization.UUID(v.Receipt.UID) && identity.Text(v.Receipt.ResourceVersion, 128)
}

func (j *InitialPreparationJournal) decode(raw []byte) (*core.ConfigMap, contracts.InitialPreparation, error) {
	var cm core.ConfigMap
	var zero contracts.InitialPreparation
	if permissionJSON(raw, 96<<10, 8192) != nil || strictGuardJSON(raw, &cm) != nil || cm.APIVersion != "v1" || cm.Kind != "ConfigMap" || cm.Namespace != j.expected.Namespace.Name || !j.creator.owns(cm.ObjectMeta, j.ref.Name) || string(cm.UID) != j.ref.UID || cm.Immutable != nil && *cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return nil, zero, cfg.ErrChanged
	}
	w, err := contracts.DecodeInitialPreparation(bytes.NewBufferString(cm.Data["preparation.json"]))
	if err != nil || w.Creates == nil || len(w.Creates) > contracts.InitialPreparationMaxCreates {
		return nil, zero, cfg.ErrChanged
	}
	root := w
	root.Creates = []contracts.InitialPreparationCreate{}
	if !equalJSON(root, j.expected) {
		return nil, zero, cfg.ErrChanged
	}
	ids, objects := map[string]bool{}, map[string]bool{}
	for i, c := range w.Creates {
		object := c.Kind + "/" + c.Name
		if !initialPreparationCreateValid(c) || ids[c.OperationID] || objects[object] || c.Receipt == nil && i != len(w.Creates)-1 {
			return nil, zero, cfg.ErrChanged
		}
		ids[c.OperationID], objects[object] = true, true
	}
	return &cm, w, nil
}

func (j *InitialPreparationJournal) current(ctx context.Context) (time.Time, error) {
	if j == nil || ctx == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	start := j.protection.guard.observer.now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	if err := j.creator.administrator(ctx); err != nil {
		return time.Time{}, err
	}
	until, err := j.protection.Current(ctx)
	if err != nil {
		return time.Time{}, err
	}
	until = identity.Earlier(until, start.Add(5*time.Second))
	if parent, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, parent)
	}
	if ctx.Err() != nil || !j.protection.guard.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}

func (j *InitialPreparationJournal) path() string {
	return "/api/v1/namespaces/" + j.expected.Namespace.Name + "/configmaps/" + j.ref.Name
}

func (j *InitialPreparationJournal) read(ctx context.Context) (*core.ConfigMap, contracts.InitialPreparation, error) {
	raw, err := j.creator.raw(ctx, j.path(), nil)
	if err != nil {
		return nil, contracts.InitialPreparation{}, cfg.ErrUnavailable
	}
	return j.decode(raw)
}

func (j *InitialPreparationJournal) finish(ctx context.Context, until time.Time) error {
	if _, err := j.current(ctx); err != nil || ctx.Err() != nil || !j.protection.guard.observer.now().Before(until) {
		return cfg.ErrUnavailable
	}
	return nil
}

func (j *InitialPreparationJournal) Read(ctx context.Context) (contracts.InitialPreparation, error) {
	var zero contracts.InitialPreparation
	until, err := j.current(ctx)
	if err != nil {
		return zero, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	_, w, err := j.read(ctx)
	if err != nil {
		return zero, err
	}
	if err := j.finish(ctx, until); err != nil {
		return zero, err
	}
	return w, nil
}

// write makes a single resource-version/UID-qualified UPDATE. Any uncertain
// result is unavailable even if a later GET might find matching state. In
// particular, that lookup can never grant Fresh after an unknown Begin result.
func (j *InitialPreparationJournal) write(ctx context.Context, cm *core.ConfigMap, w contracts.InitialPreparation, until time.Time) error {
	b, err := json.Marshal(w)
	if err != nil || len(b) > contracts.InitialPreparationMaxBytes {
		return cfg.ErrInvalid
	}
	cm.Data = map[string]string{"preparation.json": string(b)}
	raw, err := json.Marshal(cm)
	if err != nil {
		return cfg.ErrInvalid
	}
	response := j.creator.api.Put().AbsPath(j.path()).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).Do(ctx)
	raw, err = response.Raw()
	if err == nil {
		err = response.Error()
	}
	if err != nil {
		return cfg.ErrUnavailable
	}
	_, got, err := j.decode(raw)
	if err != nil || !equalJSON(got, w) {
		return cfg.ErrChanged
	}
	return j.finish(ctx, until)
}

func (j *InitialPreparationJournal) Begin(ctx context.Context, c contracts.InitialPreparationCreate) (InitialPreparationStart, error) {
	var zero InitialPreparationStart
	if c.Receipt != nil || !initialPreparationCreateValid(c) {
		return zero, cfg.ErrInvalid
	}
	until, err := j.current(ctx)
	if err != nil {
		return zero, err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	cm, w, err := j.read(ctx)
	if err != nil {
		return zero, err
	}
	for _, existing := range w.Creates {
		if existing.OperationID == c.OperationID {
			original := existing
			original.Receipt = nil
			if original != c || j.finish(ctx, until) != nil {
				return zero, cfg.ErrChanged
			}
			return InitialPreparationStart{State: w}, nil
		}
		if existing.Receipt == nil || existing.Kind == c.Kind && existing.Name == c.Name {
			return zero, cfg.ErrChanged
		}
	}
	if len(w.Creates) >= contracts.InitialPreparationMaxCreates {
		return zero, cfg.ErrInvalid
	}
	w.Creates = append(w.Creates, c)
	if err := j.write(ctx, cm, w, until); err != nil {
		return zero, err
	}
	return InitialPreparationStart{Fresh: true, State: w}, nil
}

// Observe records a separately verified exact create result. It does not
// perform the creation or validate that resource's desired public specification.
// The supervisor must retain uncertainty until that independent check succeeds.
func (j *InitialPreparationJournal) Observe(ctx context.Context, operation string, receipt contracts.InitialPreparationReceipt) error {
	if !authorization.UUID(operation) || !authorization.UUID(receipt.UID) || !identity.Text(receipt.ResourceVersion, 128) {
		return cfg.ErrInvalid
	}
	until, err := j.current(ctx)
	if err != nil {
		return err
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	cm, w, err := j.read(ctx)
	if err != nil {
		return err
	}
	for i, c := range w.Creates {
		if c.OperationID != operation {
			continue
		}
		if c.Receipt != nil {
			if *c.Receipt != receipt {
				return cfg.ErrChanged
			}
			return j.finish(ctx, until)
		}
		w.Creates[i].Receipt = &receipt
		return j.write(ctx, cm, w, until)
	}
	return cfg.ErrChanged
}
