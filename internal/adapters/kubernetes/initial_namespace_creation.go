package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const initialNamespaceRequestAnnotation = "asservat.io/preparation-request"
const initialNamespaceInstallationAnnotation = "asservat.io/installation-id"

// InitialNamespaceResources is creation provenance, not clean-history proof or
// activation authority. On failure, retain any nonempty references before retry.
type InitialNamespaceResources struct {
	Namespace cfg.NamespaceRef
	Guard     GuardPin
}

type InitialNamespaceCreator struct {
	api                   rest.Interface
	plan                  cfg.InitialNamespaceAdministration
	installation, request string
	policy                *admission.ValidatingAdmissionPolicy
	binding               *admission.ValidatingAdmissionPolicyBinding
}

// The request UUID is a previously retained private installation intent, not a
// per-retry random value. Credentials belong to trusted installation only.
func NewInitialNamespaceCreator(config *rest.Config, plan cfg.InitialNamespaceAdministration, installation, request string) (*InitialNamespaceCreator, error) {
	if !authorization.UUID(installation) || !authorization.UUID(request) {
		return nil, cfg.ErrInvalid
	}
	p, b, err := InitialNamespaceAdmission(plan)
	if err != nil {
		return nil, err
	}
	api, err := newBoundedAPI(config)
	if err != nil {
		return nil, err
	}
	plan.Administrators = append([]cfg.KubernetesActor(nil), plan.Administrators...)
	s := &InitialNamespaceCreator{api: api, plan: plan, installation: installation, request: request, policy: p, binding: b}
	s.stamp(&p.ObjectMeta)
	s.stamp(&b.ObjectMeta)
	return s, nil
}

func (s *InitialNamespaceCreator) stamp(m *meta.ObjectMeta) {
	m.Annotations = map[string]string{initialNamespaceRequestAnnotation: s.request, initialNamespaceInstallationAnnotation: s.installation}
}
func (s *InitialNamespaceCreator) owns(m meta.ObjectMeta, name string) bool {
	return m.Name == name && authorization.UUID(string(m.UID)) && identity.Text(m.ResourceVersion, 128) && m.DeletionTimestamp == nil && len(m.OwnerReferences) == 0 && m.Annotations[initialNamespaceRequestAnnotation] == s.request && m.Annotations[initialNamespaceInstallationAnnotation] == s.installation
}

func (s *InitialNamespaceCreator) raw(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	r := s.api.Get().AbsPath(path).MaxRetries(0)
	for k, v := range params {
		r.Param(k, v)
	}
	b, err := r.DoRaw(ctx)
	if err != nil {
		return nil, err
	}
	if permissionJSON(b, permissionPageBytes, 131072) != nil {
		return nil, cfg.ErrUnavailable
	}
	return b, nil
}

func (s *InitialNamespaceCreator) administrator(ctx context.Context) error {
	raw, err := s.api.Post().AbsPath("/apis/authentication.k8s.io/v1/selfsubjectreviews").Body(&auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}).MaxRetries(0).DoRaw(ctx)
	var who auth.SelfSubjectReview
	if err != nil || permissionJSON(raw, permissionPageBytes, 131072) != nil || strictGuardJSON(raw, &who) != nil || !identity.Text(who.Status.UserInfo.Username, 256) || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) {
		return cfg.ErrUnavailable
	}
	for _, a := range s.plan.Administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return nil
		}
	}
	return cfg.ErrDenied
}

// post sends one create request, with no API retry or update/adoption fallback.
// A caller receives partial pins for acknowledged effects; an unknown response
// remains unavailable. Resolving a lost process/journal is a supervisor action.
func (s *InitialNamespaceCreator) post(ctx context.Context, path string, v any) ([]byte, error) {
	if err := s.administrator(ctx); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	raw, err := s.api.Post().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(b).DoRaw(ctx)
	if err != nil {
		return nil, permissionError(ctx, err)
	}
	if permissionJSON(raw, permissionPageBytes, 131072) != nil {
		return nil, cfg.ErrUnavailable
	}
	return raw, nil
}

// CreateNew refuses an existing namespace before creating any policy. It never
// converts a name collision into a claimed fresh namespace. Nothing here creates
// probe/workload accounts, tokens, provider credentials or an installation witness.
func (s *InitialNamespaceCreator) CreateNew(ctx context.Context) (InitialNamespaceResources, error) {
	var out InitialNamespaceResources
	if s == nil || ctx == nil {
		return out, cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	if err := s.administrator(ctx); err != nil {
		return out, err
	}
	if _, err := s.raw(ctx, "/api/v1/namespaces/"+s.plan.Namespace, nil); !apierrors.IsNotFound(err) {
		if err == nil {
			return out, cfg.ErrChanged
		}
		return out, cfg.ErrUnavailable
	}
	raw, err := s.post(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", s.policy)
	if err != nil {
		return out, err
	}
	var p admission.ValidatingAdmissionPolicy
	if strictGuardJSON(raw, &p) != nil || p.APIVersion != "admissionregistration.k8s.io/v1" || p.Kind != "ValidatingAdmissionPolicy" || !s.owns(p.ObjectMeta, s.plan.Name) || p.Generation < 1 {
		return out, cfg.ErrChanged
	}
	normalizePermissionPolicy(&p.Spec)
	want := s.policy.Spec.DeepCopy()
	normalizePermissionPolicy(want)
	if !equalJSON(p.Spec, *want) {
		return out, cfg.ErrChanged
	}
	out.Guard.PolicyUID, out.Guard.PolicyGeneration = string(p.UID), p.Generation
	raw, err = s.post(ctx, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings", s.binding)
	if err != nil {
		return out, err
	}
	var b admission.ValidatingAdmissionPolicyBinding
	if strictGuardJSON(raw, &b) != nil || b.APIVersion != "admissionregistration.k8s.io/v1" || b.Kind != "ValidatingAdmissionPolicyBinding" || !s.owns(b.ObjectMeta, s.plan.Name) || !equalJSON(b.Spec, s.binding.Spec) {
		return out, cfg.ErrChanged
	}
	out.Guard.BindingUID, out.Guard.BindingResourceVersion = string(b.UID), b.ResourceVersion
	ns := core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.Namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}
	s.stamp(&ns.ObjectMeta)
	raw, err = s.post(ctx, "/api/v1/namespaces", ns)
	if err != nil {
		return out, err
	}
	// Decode into an empty value: omitted reply fields must never inherit the
	// labels or ownership stamp sent in the create request.
	ns = core.Namespace{}
	if strictGuardJSON(raw, &ns) != nil || ns.APIVersion != "v1" || ns.Kind != "Namespace" || !s.owns(ns.ObjectMeta, s.plan.Namespace) || ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		return out, cfg.ErrChanged
	}
	out.Namespace = cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}
	if ctx.Err() != nil {
		return out, cfg.ErrUnavailable
	}
	return out, nil
}

// Resume only rereads exact retained identities. It performs no create, update,
// repair, new request generation or authority renewal. The native independent
// denial and clean-history checks must still follow before credentials exist.
func (s *InitialNamespaceCreator) Resume(ctx context.Context, retained InitialNamespaceResources) error {
	if s == nil || ctx == nil || retained.Namespace.Name != s.plan.Namespace || !authorization.UUID(retained.Namespace.UID) || !authorization.UUID(retained.Guard.PolicyUID) || !authorization.UUID(retained.Guard.BindingUID) || retained.Guard.PolicyGeneration < 1 || !identity.Text(retained.Guard.BindingResourceVersion, 128) {
		return cfg.ErrInvalid
	}
	ctx, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if err := s.administrator(ctx); err != nil {
		return err
	}
	want := s.policy.Spec.DeepCopy()
	normalizePermissionPolicy(want)
	before, err := checkAdmissionGuard(ctx, s, s.plan.Name, retained.Guard, *want, s.binding.Spec)
	if err != nil {
		return err
	}
	raw, err := s.raw(ctx, "/api/v1/namespaces/"+s.plan.Namespace, nil)
	var ns core.Namespace
	if err != nil || strictGuardJSON(raw, &ns) != nil || ns.APIVersion != "v1" || ns.Kind != "Namespace" || !s.owns(ns.ObjectMeta, s.plan.Namespace) || string(ns.UID) != retained.Namespace.UID || ns.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		return cfg.ErrChanged
	}
	after, err := checkAdmissionGuard(ctx, s, s.plan.Name, retained.Guard, *want, s.binding.Spec)
	if err != nil || before != after || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	return nil
}
