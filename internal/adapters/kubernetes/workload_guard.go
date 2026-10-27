package kubernetes

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
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
	expression := capacityActors(p.Administrators) + " || (request.operation == 'CREATE' ? " + join(create) + " : " + join(unchanged) + ")"
	fail, equivalent := admission.Fail, admission.Equivalent
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail,
		MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update}, Rule: admission.Rule{APIGroups: []string{"apps"}, APIVersions: []string{"v1"}, Resources: []string{"deployments", "statefulsets"}}}}}},
		Validations:      []admission.Validation{{Expression: expression, Message: workloadMetadataDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

// WorkloadGuard proves the workload metadata guard: the pinned policy and
// binding are exactly the generated ones and the unprivileged probe
// account's dry-run CREATE of a keyed Deployment in its empty probe
// namespace is denied by exactly this guard.
type WorkloadGuard struct {
	guard *capacityGuard
	plan  cfg.WorkloadAdministration
}

func NewWorkloadGuard(observer, probe *PermissionClient, plan cfg.WorkloadAdministration, pin GuardPin) (*WorkloadGuard, error) {
	p, b, err := WorkloadAdmission(plan)
	if err != nil {
		return nil, err
	}
	g, err := newCapacityGuard(observer, probe, plan.ProbeNamespace, plan.ProbeAccount, plan.Name, plan.Administrators, nil, pin, p, b, plan)
	if err != nil {
		return nil, err
	}
	return &WorkloadGuard{guard: g, plan: plan}, nil
}

// WorkloadGuardProof is one current proof within the original interval.
func (g *WorkloadGuard) WorkloadGuardProof(ctx context.Context) (cfg.NamespaceGuardProof, error) {
	if g == nil || g.guard == nil {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx, func(call context.Context) error {
		if err := s.probeAllowed(call, "create", "apps", "deployments", s.namespace.Name, ""); err != nil {
			return err
		}
		probeLabels := map[string]string{"app.kubernetes.io/name": "asservat-workload-probe"}
		d := apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{GenerateName: "asservat-workload-probe-", Namespace: s.namespace.Name, Labels: map[string]string{}, Annotations: map[string]string{}},
			Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Selector: &meta.LabelSelector{MatchLabels: probeLabels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: probeLabels}, Spec: core.PodSpec{Containers: []core.Container{{Name: "probe", Image: "registry.invalid/asservat-workload-probe:0"}}}}}}
		if len(g.plan.LabelKeys) > 0 {
			d.Labels[g.plan.LabelKeys[0]] = "asservat-probe"
		} else {
			d.Annotations[g.plan.AnnotationKeys[0]] = "asservat-probe"
		}
		_, err := s.probe.proofPost(call, "/apis/apps/v1/namespaces/"+s.namespace.Name+"/deployments", d, map[string]string{"dryRun": "All", "fieldValidation": "Strict"})
		return capacityExactDenial(err, s.name, "apps", "deployments", workloadMetadataDenial)
	})
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

// EnsureCapacityWorkloadGuard installs the hub cluster's workload metadata
// guard over keys, with the capacity probe account of sources (ADR-247).
func EnsureCapacityWorkloadGuard(ctx context.Context, config *rest.Config, installation string, admins []cfg.KubernetesActor, sources CapacitySources, keys contracts.InstallerWorkloadKeys) (*contracts.WorkloadMetadataGuard, error) {
	api, err := installerAPI(config)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	labels, annotations := slices.Sorted(slices.Values(keys.Labels)), slices.Sorted(slices.Values(keys.Annotations))
	plan := cfg.WorkloadAdministration{Name: WorkloadGuardName(installation), Administrators: admins, LabelKeys: labels, AnnotationKeys: annotations,
		ProbeNamespace: cfg.NamespaceRef{Name: sources.ProbeNamespace.Name, UID: sources.ProbeNamespace.UID}, ProbeAccount: cfg.NamespaceRef{Name: sources.ProbeAccount.Name, UID: sources.ProbeAccount.UID}}
	g, err := EnsureWorkloadGuard(call, api, plan)
	if err != nil {
		return nil, err
	}
	return &contracts.WorkloadMetadataGuard{Guard: g, LabelKeys: labels, AnnotationKeys: annotations}, nil
}
