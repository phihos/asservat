package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const initialNamespaceDenial = "Asservat installation preparation requires the pinned administrator."

// InitialNamespaceAdmission protects setup before account/Pod UIDs exist. The
// only non-administrative exception is a nonpersistent UPDATE of the named
// public startup inputs, so this policy cannot mask the final guard's probe.
// Its own independent probe uses a distinct public ConfigMap and is denied.
func InitialNamespaceAdmission(p cfg.InitialNamespaceAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Label(p.Namespace)) != 0 || p.Namespace == "default" || strings.HasPrefix(p.Namespace, "kube-") {
		return nil, nil, cfg.ErrInvalid
	}
	for _, name := range []string{p.Name, p.ProbeSource, p.Inputs} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return nil, nil, cfg.ErrInvalid
		}
	}
	allowed := []string{}
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			allowed = append(allowed, "request.userInfo.username == "+ownerCELString(a.Name))
		} else {
			allowed = append(allowed, ownerCELString(a.Name)+" in request.userInfo.groups")
		}
	}
	allowed = append(allowed, "(has(request.dryRun) && request.dryRun && request.operation == 'UPDATE' && variables.group == '' && request.resource.resource == 'configmaps' && variables.sub == '' && request.name == "+ownerCELString(p.Inputs)+")")
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.NamespacedScope
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, Variables: []admission.Variable{{Name: "group", Expression: "has(request.resource.group) ? request.resource.group : ''"}, {Name: "sub", Expression: "has(request.subResource) ? request.subResource : ''"}}, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete, admission.Connect}, Rule: admission.Rule{APIGroups: []string{"*"}, APIVersions: []string{"*"}, Resources: []string{"*/*"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: "initial-preparation-namespace", Expression: "request.namespace == " + ownerCELString(p.Namespace)}}, Validations: []admission.Validation{{Expression: strings.Join(allowed, " || "), Message: initialNamespaceDenial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

type InitialNamespaceProtection struct{ guard *configMapProtection }

// The namespace must now exist with its actual retained UID. A current guard
// observation does not establish how this namespace was originally provisioned.
func NewInitialNamespaceProtection(observer, probe *PermissionClient, p cfg.InitialNamespaceAdministration, namespaceUID string, pin GuardPin) (*InitialNamespaceProtection, error) {
	if !authorization.UUID(namespaceUID) {
		return nil, cfg.ErrInvalid
	}
	policy, binding, err := InitialNamespaceAdmission(p)
	if err != nil {
		return nil, err
	}
	p.Administrators = append([]cfg.KubernetesActor(nil), p.Administrators...)
	plan := cfg.ConfigMapAdministration{Name: p.Name, SourceName: p.ProbeSource, ControlNamespace: cfg.NamespaceRef{Name: p.Namespace, UID: namespaceUID}, Administrators: p.Administrators}
	g, err := newConfigMapProtection(observer, probe, plan, pin, "initial-preparation-namespace", initialNamespaceDenial)
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&policy.Spec)
	raw, _ := json.Marshal(struct {
		Plan         cfg.InitialNamespaceAdministration
		NamespaceUID string
		Pin          GuardPin
	}{p, namespaceUID, pin})
	g.policy, g.binding, g.digest = policy.Spec, binding.Spec, artifact.Digest(sha256.Sum256(raw))
	return &InitialNamespaceProtection{g}, nil
}

func (g *InitialNamespaceProtection) Current(ctx context.Context) (time.Time, error) {
	if g == nil || g.guard == nil || ctx == nil {
		return time.Time{}, cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	_, until, err := g.guard.current(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if parent, ok := ctx.Deadline(); ok && parent.Before(until) {
		until = parent
	}
	if ctx.Err() != nil || !g.guard.observer.now().Before(until) {
		return time.Time{}, cfg.ErrUnavailable
	}
	return until, nil
}
