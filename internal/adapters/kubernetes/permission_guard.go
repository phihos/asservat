package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	port "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GuardPin is established through protected installation qualification. It never
// comes from a PermissionSource status, annotation, or public evidence request.
type GuardPin struct {
	PolicyUID, BindingUID, BindingResourceVersion string
	PolicyGeneration                              int64
}

// PermissionGuard is the hub control namespace's current trust observation.
// Kubernetes RBAC decides who may write PermissionSources there; the runtime
// no longer re-verifies an admission policy or proves a dry-run denial
// (helm-native-install plan, slice 0). The digest binds the cluster, plan
// and installer pin unchanged, so accepted SQL revisions stay comparable.
type PermissionGuard struct {
	observer *PermissionClient
	plan     value.PermissionAdministration
	digest   artifact.Digest
}

var _ port.PermissionTrustReader = (*PermissionGuard)(nil)

func NewPermissionGuard(observer *PermissionClient, plan value.PermissionAdministration, pin GuardPin) (*PermissionGuard, error) {
	if observer == nil || observer.control != plan.ControlNamespace {
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
	binding, _ := json.Marshal(struct {
		ClusterID string
		Plan      value.PermissionAdministration
		Pin       GuardPin
	}{observer.clusterID, own, pin})
	return &PermissionGuard{observer: observer, plan: own, digest: artifact.Digest(sha256.Sum256(binding))}, nil
}

// controlNamespaceCurrent reads the control namespace once: it must still
// exist with its original UID and not be terminating. It returns the
// observation start; the read and the result stay within interval of it.
func controlNamespaceCurrent(ctx context.Context, c *PermissionClient, ref value.NamespaceRef, interval time.Duration) (time.Time, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return time.Time{}, value.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, interval)
	start := c.now()
	defer cancel()
	ns, err := c.namespace(call, ref)
	if err != nil || ns.Deleting {
		return time.Time{}, value.ErrChanged
	}
	if err = c.current(call, start, interval); err != nil {
		return time.Time{}, err
	}
	return start, nil
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

type admissionGuardReader interface {
	raw(context.Context, string, map[string]string) ([]byte, error)
}

func checkAdmissionGuard(ctx context.Context, observer admissionGuardReader, name string, pin GuardPin, expectedPolicy admission.ValidatingAdmissionPolicySpec, expectedBinding admission.ValidatingAdmissionPolicyBindingSpec) (string, error) {
	countGuardCaller()
	raw, err := observer.raw(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+name, nil)
	if err != nil {
		return "", configurationSourceError(configurationSourceGuardPolicyRead, err)
	}
	var p admission.ValidatingAdmissionPolicy
	if err = strictGuardJSON(raw, &p); err != nil {
		return "", configurationSourceError(configurationSourceGuardPolicyDecode, err)
	}
	if p.APIVersion != "admissionregistration.k8s.io/v1" || p.Kind != "ValidatingAdmissionPolicy" || p.Name != name || string(p.UID) != pin.PolicyUID || p.Generation != pin.PolicyGeneration || p.DeletionTimestamp != nil || p.Status.ObservedGeneration > p.Generation {
		return "", configurationSourceError(configurationSourceGuardPolicyIdentity, value.ErrChanged)
	}
	// The API server type-checks a policy asynchronously (HA control planes
	// can answer before it has): until its status reaches this generation the
	// guard is pending, which callers retry within their deadline.
	if p.Status.ObservedGeneration != p.Generation || p.Status.TypeChecking == nil {
		return "", configurationSourceError(configurationSourceGuardPolicyIdentity, value.ErrUnavailable)
	}
	if len(p.Status.TypeChecking.ExpressionWarnings) != 0 {
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
func (g *PermissionGuard) PermissionTrust(ctx context.Context) (port.PermissionTrust, error) {
	var out port.PermissionTrust
	if g == nil || g.observer == nil {
		return out, value.ErrUnavailable
	}
	start, err := controlNamespaceCurrent(ctx, g.observer, g.plan.ControlNamespace, 5*time.Second)
	if err != nil {
		return out, err
	}
	return port.PermissionTrust{Digest: g.digest, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}, nil
}
