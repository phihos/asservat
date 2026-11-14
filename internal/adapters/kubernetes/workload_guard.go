package kubernetes

import (
	"context"
	"reflect"
	"slices"
	"strings"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const workloadMetadataDenial = "Asservat workload ownership administrator is required."

// WorkloadGuardProfile is the guardRef a workloadMetadata source names.
const WorkloadGuardProfile = "workload-guard"

// WorkloadAdmission is the ADR-247 workload metadata guard: on every
// Deployment and StatefulSet CREATE and UPDATE, a writer other than the
// administrators may neither set the keys on creation nor change their
// presence or values afterwards. Other metadata, spec and status are
// unaffected; the status and scale subresources do not match.
func WorkloadAdmission(p cfg.WorkloadAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Label(p.ProbeNamespace.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.ProbeAccount.Name)) != 0 {
		return nil, nil, cfg.ErrInvalid
	}
	var create, unchanged []string
	for _, field := range []struct {
		name string
		keys []string
	}{{"labels", p.LabelKeys}, {"annotations", p.AnnotationKeys}} {
		if len(field.keys) == 0 {
			continue
		}
		for _, k := range field.keys {
			if len(validation.IsQualifiedName(k)) != 0 {
				return nil, nil, cfg.ErrInvalid
			}
		}
		keys := capacityLiteral(field.keys)
		present := func(o string) string {
			return "(has(" + o + ".metadata." + field.name + ") && k in " + o + ".metadata." + field.name + ")"
		}
		create = append(create, keys+".all(k, !"+present("object")+")")
		unchanged = append(unchanged, keys+".all(k, "+present("object")+" == "+present("oldObject")+" && (!"+present("object")+" || object.metadata."+field.name+"[k] == oldObject.metadata."+field.name+"[k]))")
	}
	join := func(v []string) string {
		out := v[0]
		for _, s := range v[1:] {
			out += " && " + s
		}
		return "(" + out + ")"
	}
	foreignProbe := "(has(request.dryRun) && request.dryRun == true && request.operation == 'CREATE' && request.namespace != " + capacityLiteral(p.ProbeNamespace.Name) + ")"
	expression := capacityActors(p.Administrators) + " || " + foreignProbe + " || (request.operation == 'CREATE' ? " + join(create) + " : " + join(unchanged) + ")"
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail,
		MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update}, Rule: admission.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments", "statefulsets"}}}}}},
		Validations:      []admission.Validation{{Expression: expression, Message: workloadMetadataDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

// WorkloadGuard reports the cluster's protected workload metadata keys
// while the probe namespace still exists with its UID. Kubernetes RBAC
// decides who may write workload metadata; the runtime no longer re-verifies
// an admission policy or a dry-run denial (helm-native-install plan, slice 0).
type WorkloadGuard struct {
	guard *capacityGuard
	plan  cfg.WorkloadAdministration
}

func NewWorkloadGuard(observer *PermissionClient, plan cfg.WorkloadAdministration, pin GuardPin) (*WorkloadGuard, error) {
	if !(cfg.NamespaceKeys{Labels: plan.LabelKeys, Annotations: plan.AnnotationKeys}).Valid() || len(plan.LabelKeys)+len(plan.AnnotationKeys) == 0 {
		return nil, cfg.ErrInvalid
	}
	g, err := newCapacityGuard(observer, plan.ProbeNamespace, pin, plan)
	if err != nil {
		return nil, err
	}
	return &WorkloadGuard{guard: g, plan: plan}, nil
}

// WorkloadGuardProof is one current observation within the original interval.
func (g *WorkloadGuard) WorkloadGuardProof(ctx context.Context) (cfg.NamespaceGuardProof, error) {
	if g == nil || g.guard == nil {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx)
	if err != nil {
		return cfg.NamespaceGuardProof{}, err
	}
	return cfg.NamespaceGuardProof{ClusterID: s.observer.clusterID, Name: WorkloadGuardProfile, LabelKeys: slices.Clone(g.plan.LabelKeys), AnnotationKeys: slices.Clone(g.plan.AnnotationKeys), ObservedAt: start, FreshUntil: until}, nil
}

// WorkloadGuardName is the hub cluster's workload metadata guard.
func WorkloadGuardName(installation string) string {
	_, ns, _, _, _ := CapacitySourceNames(installation)
	return strings.TrimSuffix(ns, "-capacity-ns-guard") + "-workload-guard"
}

// EnsureWorkloadGuard creates or reopens the workload metadata guard
// (ADR-247) and its probe right: the capacity probe account may create
// Deployments in its own empty probe namespace, whose ResourceQuota admits
// no Pod, Deployment or StatefulSet, so the right serves only the dry-run
// probe. Existing objects must match exactly; nothing existing is updated.
func EnsureWorkloadGuard(call context.Context, api kubernetes.Interface, plan cfg.WorkloadAdministration) (contracts.OwnerDeploymentGuard, error) {
	var zero contracts.OwnerDeploymentGuard
	policy, binding, err := WorkloadAdmission(plan)
	if err != nil {
		return zero, err
	}
	ns, account := plan.ProbeNamespace.Name, plan.ProbeAccount.Name
	role := &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: ns + "-workload-probe", Namespace: ns}, Rules: []rbac.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}}}}
	got, err := api.RbacV1().Roles(ns).Create(call, role, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if got, err = api.RbacV1().Roles(ns).Get(call, role.Name, meta.GetOptions{}); err == nil && !reflect.DeepEqual(got.Rules, role.Rules) {
			return zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	rb := &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name, Namespace: ns}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: role.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: ns, Name: account}}}
	bound, err := api.RbacV1().RoleBindings(ns).Create(call, rb, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if bound, err = api.RbacV1().RoleBindings(ns).Get(call, rb.Name, meta.GetOptions{}); err == nil && (!reflect.DeepEqual(bound.RoleRef, rb.RoleRef) || !reflect.DeepEqual(bound.Subjects, rb.Subjects)) {
			return zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	none := resource.MustParse("0")
	quota := &core.ResourceQuota{ObjectMeta: meta.ObjectMeta{Name: ns + "-workload-probe", Namespace: ns}, Spec: core.ResourceQuotaSpec{Hard: core.ResourceList{"pods": none, "count/deployments.apps": none, "count/statefulsets.apps": none}}}
	q, err := api.CoreV1().ResourceQuotas(ns).Create(call, quota, meta.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		if q, err = api.CoreV1().ResourceQuotas(ns).Get(call, quota.Name, meta.GetOptions{}); err == nil && !equalJSON(q.Spec.Hard, quota.Spec.Hard) {
			return zero, cfg.ErrChanged
		}
	}
	if err != nil {
		return zero, cfg.ErrUnavailable
	}
	return ensureAdmissionGuard(call, api, policy, binding, plan.Administrators)
}
