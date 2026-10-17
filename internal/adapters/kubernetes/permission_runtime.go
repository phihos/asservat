package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// PermissionAdministrationOf converts the installed permission deployment's
// control section into the trusted guard plan (ADR-189). The installer and
// the hub-worker derive the same plan, so the guard digest is shared.
func PermissionAdministrationOf(c contracts.PermissionControlDeployment) cfg.PermissionAdministration {
	actors := func(v []contracts.OwnerDeploymentActor) []cfg.KubernetesActor {
		out := make([]cfg.KubernetesActor, 0, len(v))
		for _, a := range v {
			out = append(out, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
		}
		return out
	}
	p := cfg.PermissionAdministration{Name: c.Guard.Name, ControlNamespace: cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, Administrators: actors(c.Guard.Administrators), StatusUsers: append([]string(nil), c.StatusUsers...)}
	for _, d := range c.Delegations {
		scope := cfg.Scope{ClusterID: d.ClusterID, Namespace: cfg.NamespaceRef{Name: d.Namespace.Name, UID: d.Namespace.UID}}
		for _, w := range d.Workloads {
			scope.Workloads = append(scope.Workloads, cfg.WorkloadRef{Kind: w.Kind, Name: w.Name, UID: w.UID})
		}
		p.Delegations = append(p.Delegations, cfg.PermissionDelegation{Writers: actors(d.Writers), Scope: scope, Roles: append([]string(nil), d.Roles...), Issuers: append([]string(nil), d.Issuers...)})
	}
	return p
}

// RetentionAdministrationOf derives the retention guard plan (ADR-195) from
// the permission control section and the retention guard pin: the same
// administrators, the reserved status user and no delegations. The installer
// and the hub-worker derive the same plan, so the guard digest is shared.
func RetentionAdministrationOf(c contracts.PermissionControlDeployment, guard string) cfg.RetentionAdministration {
	admins := make([]cfg.KubernetesActor, 0, len(c.Guard.Administrators))
	for _, a := range c.Guard.Administrators {
		admins = append(admins, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
	}
	return cfg.RetentionAdministration{Name: guard, ControlNamespace: cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, Administrators: admins, StatusUsers: []string{contracts.RetentionStatusUser}}
}

// EnsureRetentionGuard creates or exactly reopens the retention guard and
// returns its pin, like EnsurePermissionGuard.
func EnsureRetentionGuard(ctx context.Context, config *rest.Config, plan cfg.RetentionAdministration) (contracts.OwnerDeploymentGuard, error) {
	var out contracts.OwnerDeploymentGuard
	if ctx == nil || config == nil || !plan.Valid() || !authorization.UUID(plan.ControlNamespace.UID) {
		return out, cfg.ErrInvalid
	}
	policy, binding, err := RetentionAdmission(plan)
	if err != nil {
		return out, err
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	return ensureAdmissionGuard(call, api, policy, binding, plan.Administrators)
}

// EnsurePermissionGuard creates the permission admission policy and binding,
// or reopens them only when their specs match exactly, and returns the pin of
// the acknowledged objects (ADR-189). It never updates an existing guard: a
// changed plan is a new guard revision that fences the stream.
func EnsurePermissionGuard(ctx context.Context, config *rest.Config, plan cfg.PermissionAdministration) (contracts.OwnerDeploymentGuard, error) {
	var out contracts.OwnerDeploymentGuard
	if ctx == nil || config == nil || !authorization.UUID(plan.ControlNamespace.UID) {
		return out, cfg.ErrInvalid
	}
	policy, binding, err := PermissionAdmission(plan)
	if err != nil {
		return out, err
	}
	api, err := installerAPI(config)
	if err != nil {
		return out, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	return ensureAdmissionGuard(call, api, policy, binding, plan.Administrators)
}

// ensureAdmissionGuard creates a policy and its binding, or reopens them
// only when their specs match exactly, and returns the acknowledged pin. It
// never updates an existing guard.
func ensureAdmissionGuard(call context.Context, api kubernetes.Interface, policy *admission.ValidatingAdmissionPolicy, binding *admission.ValidatingAdmissionPolicyBinding, administrators []cfg.KubernetesActor) (contracts.OwnerDeploymentGuard, error) {
	var out contracts.OwnerDeploymentGuard
	policies := api.AdmissionregistrationV1().ValidatingAdmissionPolicies()
	p, err := policies.Create(call, policy, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		// Compare after the server's defaults, as the protection reader does.
		if p, err = policies.Get(call, policy.Name, meta.GetOptions{}); err == nil {
			live, want := p.Spec.DeepCopy(), policy.Spec.DeepCopy()
			normalizePermissionPolicy(live)
			normalizePermissionPolicy(want)
			if !equalJSON(live, want) {
				return out, cfg.ErrChanged
			}
		}
	}
	if err != nil || !authorization.UUID(string(p.UID)) {
		return out, cfg.ErrUnavailable
	}
	bindings := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings()
	v, err := bindings.Create(call, binding, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if v, err = bindings.Get(call, binding.Name, meta.GetOptions{}); err == nil && !equalJSON(v.Spec, binding.Spec) {
			return out, cfg.ErrChanged
		}
	}
	if err != nil || !authorization.UUID(string(v.UID)) {
		return out, cfg.ErrUnavailable
	}
	actors := make([]contracts.OwnerDeploymentActor, 0, len(administrators))
	for _, a := range administrators {
		actors = append(actors, contracts.OwnerDeploymentActor{Kind: a.Kind, Name: a.Name})
	}
	return contracts.OwnerDeploymentGuard{Name: policy.Name, PolicyUID: string(p.UID), PolicyGeneration: p.Generation, BindingUID: string(v.UID), BindingResourceVersion: v.ResourceVersion, Administrators: actors}, nil
}
