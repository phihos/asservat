package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
