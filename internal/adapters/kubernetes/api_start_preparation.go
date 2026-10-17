package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"

	api "asservat.local/asservat/api/v1alpha1"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
)

// APIStartPreparer uses the capacity account, never the executing Pod's account.
// The only create allowance is the first acknowledged SQL preparation. A lost
// create reply recovers the original name and content, without another POST.
type APIStartPreparer struct {
	guard     *APIExecutionProtection
	startName string
	startPin  GuardPin
	policy    admission.ValidatingAdmissionPolicySpec
	binding   admission.ValidatingAdmissionPolicyBindingSpec
}

func NewAPIStartPreparer(g *APIExecutionProtection, name string, pin GuardPin) (*APIStartPreparer, error) {
	if g == nil || !identity.Text(pin.PolicyUID, 64) || pin.PolicyGeneration < 1 || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) {
		return nil, value.ErrInvalid
	}
	p := g.plan
	policy, binding, err := StartAdmission(configuration.LocalStartAdministration{Name: name, ControlNamespace: p.ControlNamespace, CapacityUser: "system:serviceaccount:" + p.ControlNamespace.Name + ":" + p.CapacityAccount, ExecutionUser: "system:serviceaccount:" + p.ControlNamespace.Name + ":" + p.Account})
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&policy.Spec)
	return &APIStartPreparer{g, name, pin, policy.Spec, binding.Spec}, nil
}
func (p *APIStartPreparer) check(ctx context.Context, c value.PreparationCheck) error {
	if p == nil || !c.Valid(p.guard.observer.now()) || c.Binding.ClusterID != p.guard.plan.ClusterID || c.Binding.IssuerEpoch != p.guard.plan.IssuerEpoch || c.Binding.ExecutorPodUID != p.guard.plan.PodUID || c.Binding.ExecutorAccountUID != p.guard.plan.AccountUID {
		return value.ErrDenied
	}
	until, err := p.guard.current(ctx)
	if err != nil {
		return err
	}
	if err = p.guard.account(ctx, p.guard.observer, p.guard.plan.CapacityAccount, p.guard.plan.CapacityAccountUID, false); err != nil {
		return err
	}
	if _, err = checkAdmissionGuard(ctx, p.guard.observer, p.startName, p.startPin, p.policy, p.binding); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	now := p.guard.observer.now()
	if !c.Valid(now) || !now.Before(until) {
		return value.ErrExpired
	}
	return nil
}
func (p *APIStartPreparer) path(b value.Binding) string {
	return "/apis/asservat.io/v1alpha1/namespaces/" + p.guard.plan.ControlNamespace.Name + "/capacityreservations/start-" + b.AttemptID
}
func preparedStart(raw []byte, b value.Binding, namespace string) (startObject, value.PreparedStart, error) {
	var o startObject
	if permissionJSON(raw, 16<<10, 2048) != nil {
		return o, value.PreparedStart{}, value.ErrUnavailable
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&o) != nil || o.APIVersion != "asservat.io/v1alpha1" || o.Kind != "CapacityReservation" {
		return o, value.PreparedStart{}, value.ErrUnavailable
	}
	canonical, _ := json.Marshal(o)
	if !startKeys(raw, canonical, true) {
		return o, value.PreparedStart{}, value.ErrUnavailable
	}
	m, err := decodeMetadata(o.Metadata, false)
	expected, e := LocalStartSpec(b)
	var meta struct {
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		OwnerReferences   []json.RawMessage `json:"ownerReferences"`
		Finalizers        []string          `json:"finalizers"`
	}
	if err != nil || e != nil || json.Unmarshal(o.Metadata, &meta) != nil || m.Name != "start-"+b.AttemptID || m.Namespace != namespace || m.Generation != 1 || o.Spec != expected || meta.DeletionTimestamp != nil || len(meta.OwnerReferences) > 0 || len(meta.Finalizers) > 0 {
		return o, value.PreparedStart{}, value.ErrConflict
	}
	out := value.PreparedStart{ObjectUID: m.UID, ResourceVersion: m.RV}
	if o.Status != nil {
		_, _, err = decodeStart(raw, value.Request{Binding: b, ObjectUID: m.UID}, namespace)
		if err != nil {
			return o, value.PreparedStart{}, err
		}
	}
	return o, out, nil
}
func (p *APIStartPreparer) PrepareStart(ctx context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	if p == nil || ctx == nil {
		return value.PreparedStart{}, value.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, c.ValidUntil)
	defer cancel()
	if err := p.check(ctx, c); err != nil {
		return value.PreparedStart{}, err
	}
	var raw []byte
	var err error
	if c.MayCreate {
		spec, _ := LocalStartSpec(c.Binding)
		metadata, _ := json.Marshal(map[string]string{"name": "start-" + c.Binding.AttemptID, "namespace": p.guard.plan.ControlNamespace.Name})
		payload, _ := json.Marshal(startObject{APIVersion: "asservat.io/v1alpha1", Kind: "CapacityReservation", Metadata: metadata, Spec: spec})
		raw, err = p.guard.observer.api.Post().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + p.guard.plan.ControlNamespace.Name + "/capacityreservations").MaxRetries(0).Body(payload).DoRaw(ctx)
	} else {
		raw, err = p.guard.observer.api.Get().AbsPath(p.path(c.Binding)).MaxRetries(0).DoRaw(ctx)
	}
	if err != nil {
		return value.PreparedStart{}, startError(ctx, err)
	}
	_, out, err := preparedStart(raw, c.Binding, p.guard.plan.ControlNamespace.Name)
	if err != nil {
		return value.PreparedStart{}, err
	}
	if err = p.check(ctx, c); err != nil {
		return value.PreparedStart{}, err
	}
	return out, nil
}

// ReadyStart requires the original UID already recorded by SQL. Replay can
// observe Ready/StartCommitted, but this role never returns MayStart.
func (p *APIStartPreparer) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	var zero value.Disposition
	if p == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, r.ValidUntil)
	defer cancel()
	c := value.PreparationCheck{Binding: r.Binding, CheckedAt: r.CheckedAt, ValidUntil: r.ValidUntil}
	if err := r.Validate(p.guard.observer.now()); err != nil {
		return zero, err
	}
	if err := p.check(ctx, c); err != nil {
		return zero, err
	}
	raw, err := p.guard.observer.api.Get().AbsPath(p.path(r.Binding)).MaxRetries(0).DoRaw(ctx)
	if err != nil {
		return zero, startError(ctx, err)
	}
	o, prepared, err := preparedStart(raw, r.Binding, p.guard.plan.ControlNamespace.Name)
	if err != nil {
		return zero, err
	}
	if prepared.ObjectUID != r.ObjectUID {
		return zero, value.ErrConflict
	}
	if o.Status == nil {
		if err = p.check(ctx, c); err != nil {
			return zero, err
		}
		o.Status = &api.LocalStartStatus{Phase: string(value.Ready)}
		payload, _ := json.Marshal(o)
		raw, err = p.guard.observer.api.Put().AbsPath(p.path(r.Binding) + "/status").MaxRetries(0).Body(payload).DoRaw(ctx)
		if err != nil {
			return zero, startError(ctx, err)
		}
	}
	_, out, err := decodeStart(raw, r, p.guard.plan.ControlNamespace.Name)
	if err != nil {
		return zero, err
	}
	if err = p.check(ctx, c); err != nil {
		return zero, err
	}
	return out, nil
}

// Keep all time bounds in caller-owned observations; no Ready response extends
// the original five-second interval, SQL preparation, or collection deadline.
