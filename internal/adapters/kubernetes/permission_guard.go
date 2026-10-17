package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GuardPin is established through protected installation qualification. It never
// comes from a PermissionSource status, annotation, or public evidence request.
type GuardPin struct {
	PolicyUID, BindingUID, BindingResourceVersion string
	PolicyGeneration                              int64
}
type PermissionGuard struct {
	observer, probe *PermissionClient
	plan            value.PermissionAdministration
	pin             GuardPin
	expectedPolicy  admission.ValidatingAdmissionPolicySpec
	expectedBinding admission.ValidatingAdmissionPolicyBindingSpec
	digest          artifact.Digest
}

var _ port.PermissionTrustReader = (*PermissionGuard)(nil)

func NewPermissionGuard(observer, probe *PermissionClient, plan value.PermissionAdministration, pin GuardPin) (*PermissionGuard, error) {
	if observer == nil || probe == nil || observer == probe || observer.clusterID != probe.clusterID || observer.control != plan.ControlNamespace || probe.control != plan.ControlNamespace || !identity.Text(pin.PolicyUID, 64) || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) || pin.PolicyGeneration < 1 {
		return nil, value.ErrInvalid
	}
	// Keep caller-owned slices out of the live trust object.
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, value.ErrInvalid
	}
	var own value.PermissionAdministration
	if json.Unmarshal(encoded, &own) != nil {
		return nil, value.ErrInvalid
	}
	p, b, err := PermissionAdmission(own)
	if err != nil {
		return nil, err
	}
	normalizePermissionPolicy(&p.Spec)
	binding, _ := json.Marshal(struct {
		ClusterID string
		Plan      value.PermissionAdministration
		Pin       GuardPin
	}{observer.clusterID, own, pin})
	return &PermissionGuard{observer: observer, probe: probe, plan: own, pin: pin, expectedPolicy: p.Spec, expectedBinding: b.Spec, digest: artifact.Digest(sha256.Sum256(binding))}, nil
}
func normalizePermissionPolicy(p *admission.ValidatingAdmissionPolicySpec) {
	if p.MatchConstraints == nil {
		return
	}
	if p.MatchConstraints.NamespaceSelector == nil {
		p.MatchConstraints.NamespaceSelector = &metav1.LabelSelector{}
	}
	if p.MatchConstraints.ObjectSelector == nil {
		p.MatchConstraints.ObjectSelector = &metav1.LabelSelector{}
	}
	for i := range p.MatchConstraints.ResourceRules {
		if p.MatchConstraints.ResourceRules[i].Scope == nil {
			scope := admission.AllScopes
			p.MatchConstraints.ResourceRules[i].Scope = &scope
		}
	}
}
func equalJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func strictGuardJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return value.ErrUnavailable
	}
	return nil
}
func (g *PermissionGuard) check(ctx context.Context) (string, error) {
	return checkAdmissionGuard(ctx, g.observer, g.plan.Name, g.pin, g.expectedPolicy, g.expectedBinding)
}

type admissionGuardReader interface {
	raw(context.Context, string, map[string]string) ([]byte, error)
}

func checkAdmissionGuard(ctx context.Context, observer admissionGuardReader, name string, pin GuardPin, expectedPolicy admission.ValidatingAdmissionPolicySpec, expectedBinding admission.ValidatingAdmissionPolicyBindingSpec) (string, error) {
	raw, err := observer.raw(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+name, nil)
	if err != nil {
		return "", configurationSourceError(configurationSourceGuardPolicyRead, err)
	}
	var p admission.ValidatingAdmissionPolicy
	if err = strictGuardJSON(raw, &p); err != nil {
		return "", configurationSourceError(configurationSourceGuardPolicyDecode, err)
	}
	if p.APIVersion != "admissionregistration.k8s.io/v1" || p.Kind != "ValidatingAdmissionPolicy" || p.Name != name || string(p.UID) != pin.PolicyUID || p.Generation != pin.PolicyGeneration || p.DeletionTimestamp != nil || p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil || len(p.Status.TypeChecking.ExpressionWarnings) != 0 {
		return "", configurationSourceError(configurationSourceGuardPolicyIdentity, value.ErrChanged)
	}
	normalizePermissionPolicy(&p.Spec)
	if !equalJSON(p.Spec, expectedPolicy) {
		return "", configurationSourceError(configurationSourceGuardPolicySpec, value.ErrChanged)
	}
	raw, err = observer.raw(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/"+name, nil)
	if err != nil {
		return "", configurationSourceError(configurationSourceGuardBindingRead, err)
	}
	var b admission.ValidatingAdmissionPolicyBinding
	if err = strictGuardJSON(raw, &b); err != nil {
		return "", configurationSourceError(configurationSourceGuardBindingDecode, err)
	}
	if b.APIVersion != "admissionregistration.k8s.io/v1" || b.Kind != "ValidatingAdmissionPolicyBinding" || b.Name != name || string(b.UID) != pin.BindingUID || b.ResourceVersion != pin.BindingResourceVersion || b.DeletionTimestamp != nil || !equalJSON(b.Spec, expectedBinding) {
		return "", configurationSourceError(configurationSourceGuardBindingIdentity, value.ErrChanged)
	}
	return p.ResourceVersion, nil
}
func (c *PermissionClient) proofPost(ctx context.Context, path string, body any, params map[string]string) ([]byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, value.ErrInvalid
	}
	r := c.api.Post().AbsPath(path).MaxRetries(0).Body(encoded)
	for k, v := range params {
		r.Param(k, v)
	}
	response := r.Do(ctx)
	raw, err := response.Raw()
	if err = permissionJSON(raw, permissionPageBytes, 131072); err != nil {
		return nil, err
	}
	// DoRaw discards structured Status details. Admission proof needs the exact
	// authenticated policy cause, so decode the bounded, checked error body.
	if err = response.Error(); err != nil {
		return nil, err
	}
	return raw, nil
}
func actorMatches(a value.KubernetesActor, u authentication.UserInfo) bool {
	if a.Kind == "User" {
		return a.Name == u.Username
	}
	for _, group := range u.Groups {
		if a.Name == group {
			return true
		}
	}
	return false
}
func (g *PermissionGuard) proveDenial(ctx context.Context) error {
	raw, err := g.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: metav1.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	if err != nil {
		return value.ErrUnavailable
	}
	var who authentication.SelfSubjectReview
	if strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return value.ErrUnavailable
	}
	for _, a := range g.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return value.ErrInvalid
		}
	}
	for _, d := range g.plan.Delegations {
		for _, a := range d.Writers {
			if actorMatches(a, who.Status.UserInfo) {
				return value.ErrInvalid
			}
		}
	}
	// A native RBAC denial cannot masquerade as proof of admission enforcement.
	review := authorization.SelfSubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Namespace: g.plan.ControlNamespace.Name, Verb: "create", Group: "asservat.io", Version: "v1alpha1", Resource: "accessbindings"}}}
	raw, err = g.probe.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, nil)
	if err != nil {
		return value.ErrUnavailable
	}
	var access authorization.SelfSubjectAccessReview
	if strictGuardJSON(raw, &access) != nil || !access.Status.Allowed || access.Status.Denied || access.Status.EvaluationError != "" {
		return value.ErrUnavailable
	}
	probe := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "AccessBinding", "metadata": map[string]any{"generateName": "asservat-guard-probe-", "namespace": g.plan.ControlNamespace.Name}, "spec": map[string]any{"effect": "Deny", "roles": []string{"evidence-reader"}, "subjects": []map[string]string{{"kind": "User", "issuer": "https://guard-probe.invalid", "id": "non-authorizing-probe"}}, "scope": map[string]any{"clusterID": g.observer.clusterID, "namespaceRef": map[string]string{"name": g.plan.ControlNamespace.Name, "uid": g.plan.ControlNamespace.UID}}, "reason": "Synthetic admission validation; dry run only"}}
	_, err = g.probe.proofPost(ctx, "/apis/asservat.io/v1alpha1/namespaces/"+g.plan.ControlNamespace.Name+"/accessbindings", probe, map[string]string{"dryRun": "All", "fieldValidation": "Strict"})
	expected := "ValidatingAdmissionPolicy '" + g.plan.Name + "' with binding '" + g.plan.Name + "' denied request: Asservat permission administrator or matching delegation is required."
	var status apierrors.APIStatus
	if (!apierrors.IsForbidden(err) && !apierrors.IsInvalid(err)) || !errors.As(err, &status) {
		return value.ErrUnavailable
	}
	denial := status.Status()
	if denial.Details == nil || denial.Details.Group != "asservat.io" || denial.Details.Kind != "accessbindings" || len(denial.Details.Causes) > 8 {
		return value.ErrUnavailable
	}
	for _, cause := range denial.Details.Causes {
		if cause.Message == expected {
			return nil
		}
	}
	return value.ErrUnavailable
}
func (g *PermissionGuard) PermissionTrust(ctx context.Context) (port.PermissionTrust, error) {
	var out port.PermissionTrust
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := g.observer.now()
	ns, err := g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return out, value.ErrChanged
	}
	version, err := g.check(ctx)
	if err != nil {
		return out, err
	}
	if err = g.proveDenial(ctx); err != nil {
		return out, err
	}
	after, err := g.check(ctx)
	if err != nil || after != version {
		return out, value.ErrChanged
	}
	ns, err = g.observer.namespace(ctx, g.plan.ControlNamespace)
	if err != nil || ns.Deleting {
		return out, value.ErrChanged
	}
	if err = g.observer.current(ctx, start, 5*time.Second); err != nil {
		return out, err
	}
	return port.PermissionTrust{Digest: g.digest, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, nil
}
