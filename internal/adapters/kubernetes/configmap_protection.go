package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func configMapAdmission(p value.ConfigMapAdministration, condition, denial string) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error) {
	if !p.Valid() || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || len(validation.IsDNS1123Subdomain(p.SourceName)) != 0 || len(validation.IsDNS1123Label(p.ControlNamespace.Name)) != 0 {
		return nil, nil, value.ErrInvalid
	}
	literal := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	var actors []string
	for _, a := range p.Administrators {
		if a.Kind == "User" {
			actors = append(actors, "request.userInfo.username == "+literal(a.Name))
		} else {
			actors = append(actors, literal(a.Name)+" in request.userInfo.groups")
		}
	}
	fail, equivalent, scope := admission.Fail, admission.Equivalent, admission.NamespacedScope
	policy := &admission.ValidatingAdmissionPolicy{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{ResourceNames: []string{p.SourceName}, RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create, admission.Update, admission.Delete}, Rule: admission.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}, Scope: &scope}}}}}, MatchConditions: []admission.MatchCondition{{Name: condition, Expression: "request.namespace == " + literal(p.ControlNamespace.Name)}}, Validations: []admission.Validation{{Expression: strings.Join(actors, " || "), Message: denial}}}}
	binding := &admission.ValidatingAdmissionPolicyBinding{TypeMeta: meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}, ObjectMeta: meta.ObjectMeta{Name: p.Name}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: p.Name, ValidationActions: []admission.ValidationAction{admission.Deny}}}
	return policy, binding, nil
}

type configMapProtection struct {
	observer, probe *PermissionClient
	plan            value.ConfigMapAdministration
	pin             GuardPin
	policy          admission.ValidatingAdmissionPolicySpec
	binding         admission.ValidatingAdmissionPolicyBindingSpec
	digest          artifact.Digest
	denial          string
}

func newConfigMapProtection(observer, probe *PermissionClient, plan value.ConfigMapAdministration, pin GuardPin, condition, denial string) (*configMapProtection, error) {
	// Helm-native installation (ADR-328): the probe and pin are optional
	// leftovers of the admission guard; callers outside the hub-api may
	// still pass them for their remaining proofs.
	if observer == nil || observer == probe || probe != nil && (observer.clusterID != probe.clusterID || probe.control != plan.ControlNamespace) || observer.control != plan.ControlNamespace {
		return nil, value.ErrInvalid
	}
	plan.Administrators = append([]value.KubernetesActor(nil), plan.Administrators...)
	out := &configMapProtection{observer: observer, probe: probe, plan: plan, pin: pin, digest: artifact.Digest(contracts.ConfigMapSourceDigest(observer.clusterID, plan.ControlNamespace.Name, plan.SourceName)), denial: denial}
	if probe == nil {
		if len(validation.IsDNS1123Subdomain(plan.SourceName)) != 0 || len(validation.IsDNS1123Label(plan.ControlNamespace.Name)) != 0 {
			return nil, value.ErrInvalid
		}
		return out, nil
	}
	p, b, e := configMapAdmission(plan, condition, denial)
	if e != nil {
		return nil, e
	}
	normalizePermissionPolicy(&p.Spec)
	out.policy, out.binding = p.Spec, b.Spec
	return out, nil
}
func (g *configMapProtection) prove(ctx context.Context) error {
	_, err := g.proveObject(ctx)
	return err
}

// The returned object is the actual GET used by this independently denied
// dry-run. Purpose-specific callers may validate its complete body within the
// same original bracket; it cannot represent a second or newer observation.
func (g *configMapProtection) proveObject(ctx context.Context) (core.ConfigMap, error) {
	object, _, err := g.proveObjectIdentity(ctx)
	return object, err
}

// The identity is from this exact denied probe's actual SelfSubjectReview.
// It is not a credential and cannot replace a live account/body predicate.
func (g *configMapProtection) proveObjectIdentity(ctx context.Context) (core.ConfigMap, authentication.UserInfo, error) {
	var zero core.ConfigMap
	if g.probe == nil {
		return zero, authentication.UserInfo{}, value.ErrUnavailable
	}
	raw, e := g.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	if e != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeIdentityRead, value.ErrUnavailable)
	}
	var who authentication.SelfSubjectReview
	if strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeIdentityShape, value.ErrUnavailable)
	}
	for _, a := range g.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAdministrator, value.ErrInvalid)
		}
	}
	review := authorization.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: g.plan.ControlNamespace.Name, Verb: "update", Group: "", Version: "v1", Resource: "configmaps", Name: g.plan.SourceName}}}
	raw, e = g.probe.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, nil)
	if e != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAccessRead, value.ErrUnavailable)
	}
	var access authorization.SelfSubjectAccessReview
	if strictGuardJSON(raw, &access) != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeAccessVerdict, value.ErrUnavailable)
	}
	path := "/api/v1/namespaces/" + g.plan.ControlNamespace.Name + "/configmaps/" + g.plan.SourceName
	raw, e = g.observer.raw(ctx, path, nil)
	if e != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeObjectRead, e)
	}
	var object core.ConfigMap
	if json.Unmarshal(raw, &object) != nil || object.Name != g.plan.SourceName || object.Namespace != g.plan.ControlNamespace.Name || object.DeletionTimestamp != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeObjectShape, value.ErrUnavailable)
	}
	// Re-submit the existing value as an UPDATE with dryRun=All. It cannot
	// persist anything even if admission is absent or becomes unavailable.
	response := g.probe.api.Put().AbsPath(path).Param("dryRun", "All").Param("fieldValidation", "Strict").Body(raw).MaxRetries(0).Do(ctx)
	raw, e = response.Raw()
	if permissionJSON(raw, permissionPageBytes, 131072) != nil {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialBody, value.ErrUnavailable)
	}
	e = response.Error()
	var status apierrors.APIStatus
	if (!apierrors.IsForbidden(e) && !apierrors.IsInvalid(e)) || !errors.As(e, &status) {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialStatus, value.ErrUnavailable)
	}
	d := status.Status()
	if d.Details == nil || d.Details.Group != "" || d.Details.Kind != "configmaps" || len(d.Details.Causes) > 8 {
		return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialDetails, value.ErrUnavailable)
	}
	expected := "ValidatingAdmissionPolicy '" + g.plan.Name + "' with binding '" + g.plan.Name + "' denied request: " + g.denial
	for _, c := range d.Details.Causes {
		if c.Message == expected {
			return object, who.Status.UserInfo, nil
		}
	}
	return zero, authentication.UserInfo{}, configurationSourceError(configurationSourceProbeDenialCause, value.ErrUnavailable)
}

// Proven proves the guard against its existing source and returns the
// protection digest the runtime checks, so an installer pins exactly what
// the runtime will compute (ADR-196 decision 7).
func (g *configMapProtection) Proven(ctx context.Context) (artifact.Digest, error) {
	d, _, err := g.current(ctx)
	return d, err
}

func (g *configMapProtection) current(ctx context.Context) (artifact.Digest, time.Time, error) {
	var zero artifact.Digest
	if g == nil || g.probe == nil {
		return zero, time.Time{}, value.ErrInvalid
	}
	start := g.observer.now()
	ns, e := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if e != nil || ns.Deleting {
		return zero, time.Time{}, value.ErrChanged
	}
	before, e := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if e != nil {
		return zero, time.Time{}, e
	}
	if e = g.prove(ctx); e != nil {
		return zero, time.Time{}, e
	}
	after, e := checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.policy, g.binding)
	if e != nil || before != after || g.observer.current(ctx, start, 5*time.Second) != nil {
		return zero, time.Time{}, value.ErrChanged
	}
	return g.digest, start.Add(5 * time.Second), nil
}

// observe is the runtime's view of a source (Helm-native install plan, slice
// 0): ordinary Kubernetes RBAC protects the named ConfigMap, so the runtime no
// longer re-verifies admission guards, probe identities or denied dry-runs.
// Callers read the source with plain bounded GETs within the returned original
// five-second window. The digest is the unchanged configuration digest that
// observations persist; it no longer attests a proven admission guard. The
// probing methods above remain only for the installer until it is removed.
func (g *configMapProtection) observe(ctx context.Context) (artifact.Digest, time.Time, error) {
	if g == nil || ctx == nil {
		return artifact.Digest{}, time.Time{}, value.ErrInvalid
	}
	if ctx.Err() != nil {
		return artifact.Digest{}, time.Time{}, value.ErrUnavailable
	}
	return g.digest, g.observer.now().Add(5 * time.Second), nil
}

// read is one plain bounded GET of the named source ConfigMap by the runtime's
// own client. Purpose-specific callers validate the complete body.
func (g *configMapProtection) read(ctx context.Context) (core.ConfigMap, error) {
	var zero core.ConfigMap
	if g == nil || ctx == nil {
		return zero, value.ErrInvalid
	}
	raw, e := g.observer.raw(ctx, "/api/v1/namespaces/"+g.plan.ControlNamespace.Name+"/configmaps/"+g.plan.SourceName, nil)
	if e != nil {
		return zero, configurationSourceError(configurationSourceProbeObjectRead, e)
	}
	var object core.ConfigMap
	if json.Unmarshal(raw, &object) != nil || object.Name != g.plan.SourceName || object.Namespace != g.plan.ControlNamespace.Name || object.DeletionTimestamp != nil {
		return zero, configurationSourceError(configurationSourceProbeObjectShape, value.ErrUnavailable)
	}
	return object, nil
}
