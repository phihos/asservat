package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	api "asservat.local/asservat/api/v1alpha1"
	port "asservat.local/asservat/internal/application/execution"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ port.ObservedAPIStartPreparation = (*ConnectorAPIStartPreparer)(nil)

// ConnectorAPIStartPreparer shares the closed start body/CAS semantics with the
// bare-Pod preparer, but uses the independently installed connector API profile.
// The distinct capacity client never supplies execution or administration.
type ConnectorAPIStartPreparer struct {
	process  *ConnectorAPIExecutionProcess
	capacity *PermissionClient
	policy   admission.ValidatingAdmissionPolicySpec
	binding  admission.ValidatingAdmissionPolicyBindingSpec
	pin      GuardPin
}

func NewConnectorAPIStartPreparer(p *ConnectorAPIExecutionProcess, capacity *PermissionClient) (*ConnectorAPIStartPreparer, error) {
	if p == nil || p.guard == nil || capacity == nil || capacity == p.guard.attester.client || capacity.clusterID != p.guard.installed.ClusterID || capacity.control != p.guard.attester.client.control {
		return nil, value.ErrInvalid
	}
	s := p.guard.installed
	policy, binding, e := StartAdmission(cfg.LocalStartAdministration{Name: s.StartGuard.Name, ControlNamespace: capacity.control, CapacityUser: "system:serviceaccount:" + s.Namespace + ":" + s.CapacityAccount, ExecutionUser: "system:serviceaccount:" + s.Namespace + ":" + s.Account})
	if e != nil {
		return nil, e
	}
	normalizePermissionPolicy(&policy.Spec)
	pin := GuardPin{PolicyUID: s.StartGuard.PolicyUID, PolicyGeneration: s.StartGuard.PolicyGeneration, BindingUID: s.StartGuard.BindingUID, BindingResourceVersion: s.StartGuard.BindingResourceVersion}
	return &ConnectorAPIStartPreparer{p, capacity, policy.Spec, binding.Spec, pin}, nil
}

// check reads the process unless the caller supplies the work's complete
// observation (ADR-173). That observation must be this process's own and still
// within its original interval; capacity, account and start-guard checks below
// stay current on every call.
func (p *ConnectorAPIStartPreparer) check(ctx context.Context, c value.PreparationCheck, observed *value.APIProcessObservation) (time.Time, error) {
	if p == nil || ctx == nil || !c.Valid(p.capacity.now()) {
		return time.Time{}, value.ErrDenied
	}
	var process value.APIProcessObservation
	var e error
	if observed != nil {
		process = *observed
		if process.Binding != p.process.binding || !process.Valid(p.capacity.now()) {
			return time.Time{}, value.ErrDenied
		}
	} else if process, e = p.process.ReadAPIProcess(ctx); e != nil {
		return time.Time{}, value.ErrDenied
	}
	if !process.Matches(c.Binding) {
		return time.Time{}, value.ErrDenied
	}
	until := identity.Earlier(c.ValidUntil, process.ValidUntil)
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	s := p.process.guard.installed
	raw, e := p.capacity.proofPost(call, "/apis/authentication.k8s.io/v1/selfsubjectreviews", auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who auth.SelfSubjectReview
	if e != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+s.Namespace+":"+s.CapacityAccount || who.Status.UserInfo.UID != s.CapacityAccountUID {
		return time.Time{}, value.ErrDenied
	}
	for _, a := range p.process.guard.attester.protection.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return time.Time{}, value.ErrDenied
		}
	}
	raw, e = p.process.guard.attester.client.raw(call, "/api/v1/namespaces/"+s.Namespace+"/serviceaccounts/"+s.CapacityAccount, nil)
	var account core.ServiceAccount
	if e != nil || json.Unmarshal(raw, &account) != nil || account.APIVersion != "v1" || account.Kind != "ServiceAccount" || !ownerMetadata(account.ObjectMeta, s.Namespace, s.CapacityAccount, s.CapacityAccountUID) {
		return time.Time{}, value.ErrDenied
	}
	if _, e = checkAdmissionGuard(call, p.process.guard.attester.client, s.StartGuard.Name, p.pin, p.policy, p.binding); e != nil {
		return time.Time{}, e
	}
	if call.Err() != nil || !c.Valid(p.capacity.now()) || !process.Valid(p.capacity.now()) || !p.capacity.now().Before(until) {
		return time.Time{}, value.ErrExpired
	}
	return until, nil
}
func (p *ConnectorAPIStartPreparer) path(b value.Binding) string {
	return "/apis/asservat.io/v1alpha1/namespaces/" + p.capacity.control.Name + "/capacityreservations/start-" + b.AttemptID
}
func (p *ConnectorAPIStartPreparer) PrepareStart(ctx context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	return p.prepare(ctx, c, nil)
}
func (p *ConnectorAPIStartPreparer) PrepareObservedStart(ctx context.Context, c value.PreparationCheck, process value.APIProcessObservation) (value.PreparedStart, error) {
	return p.prepare(ctx, c, &process)
}
func (p *ConnectorAPIStartPreparer) prepare(ctx context.Context, c value.PreparationCheck, observed *value.APIProcessObservation) (value.PreparedStart, error) {
	var zero value.PreparedStart
	if p == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, c.ValidUntil)
	defer cancel()
	until, e := p.check(call, c, observed)
	if e != nil {
		return zero, e
	}
	call, stop := context.WithDeadline(call, until)
	defer stop()
	var raw []byte
	if c.MayCreate {
		spec, e := LocalStartSpec(c.Binding)
		if e != nil {
			return zero, e
		}
		metadata, _ := json.Marshal(map[string]string{"name": "start-" + c.Binding.AttemptID, "namespace": p.capacity.control.Name})
		body, _ := json.Marshal(startObject{APIVersion: "asservat.io/v1alpha1", Kind: "CapacityReservation", Metadata: metadata, Spec: spec})
		raw, e = p.capacity.api.Post().AbsPath("/apis/asservat.io/v1alpha1/namespaces/" + p.capacity.control.Name + "/capacityreservations").MaxRetries(0).Body(body).DoRaw(call)
	} else {
		raw, e = p.capacity.api.Get().AbsPath(p.path(c.Binding)).MaxRetries(0).DoRaw(call)
	}
	if e != nil {
		return zero, startError(call, e)
	}
	_, out, e := preparedStart(raw, c.Binding, p.capacity.control.Name)
	if e != nil {
		return zero, e
	}
	if _, e = p.check(call, c, observed); e != nil {
		return zero, e
	}
	if call.Err() != nil || !p.capacity.now().Before(until) {
		return zero, value.ErrExpired
	}
	return out, nil
}
func (p *ConnectorAPIStartPreparer) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	return p.ready(ctx, r, nil)
}
func (p *ConnectorAPIStartPreparer) ReadyObservedStart(ctx context.Context, r value.Request, process value.APIProcessObservation) (value.Disposition, error) {
	return p.ready(ctx, r, &process)
}
func (p *ConnectorAPIStartPreparer) ready(ctx context.Context, r value.Request, observed *value.APIProcessObservation) (value.Disposition, error) {
	var zero value.Disposition
	if p == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	if e := r.Validate(p.capacity.now()); e != nil {
		return zero, e
	}
	c := value.PreparationCheck{Binding: r.Binding, CheckedAt: r.CheckedAt, ValidUntil: r.ValidUntil}
	call, cancel := context.WithDeadline(ctx, r.ValidUntil)
	defer cancel()
	until, e := p.check(call, c, observed)
	if e != nil {
		return zero, e
	}
	call, stop := context.WithDeadline(call, until)
	defer stop()
	raw, e := p.capacity.api.Get().AbsPath(p.path(r.Binding)).MaxRetries(0).DoRaw(call)
	if e != nil {
		return zero, startError(call, e)
	}
	o, prepared, e := preparedStart(raw, r.Binding, p.capacity.control.Name)
	if e != nil {
		return zero, e
	}
	if prepared.ObjectUID != r.ObjectUID {
		return zero, value.ErrConflict
	}
	if o.Status == nil {
		last, e := p.check(call, c, observed)
		if e != nil {
			return zero, e
		}
		until = identity.Earlier(until, last)
		var beforePut context.CancelFunc
		call, beforePut = context.WithDeadline(call, until)
		defer beforePut()
		o.Status = &api.LocalStartStatus{Phase: string(value.Ready)}
		body, _ := json.Marshal(o)
		raw, e = p.capacity.api.Put().AbsPath(p.path(r.Binding) + "/status").MaxRetries(0).Body(body).DoRaw(call)
		if e != nil {
			return zero, startError(call, e)
		}
	}
	_, out, e := decodeStart(raw, r, p.capacity.control.Name)
	if e != nil {
		return zero, e
	}
	if _, e = p.check(call, c, observed); e != nil {
		return zero, e
	}
	if call.Err() != nil || !p.capacity.now().Before(until) {
		return zero, value.ErrExpired
	}
	return out, nil
}
