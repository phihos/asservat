package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	port "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Only these two capacity-specific guards share this private state. A current
// denial does not establish historical namespace cleanliness or recovery.
type capacityGuard struct {
	observer, probe    *PermissionClient
	namespace, account cfg.NamespaceRef
	name               string
	administrators     []cfg.KubernetesActor
	statusUsers        []string
	pin                GuardPin
	policy             admission.ValidatingAdmissionPolicySpec
	binding            admission.ValidatingAdmissionPolicyBindingSpec
	digest             artifact.Digest
}
type CapacityGuard struct{ guard *capacityGuard }
type CapacityNamespaceGuard struct {
	guard *capacityGuard
	keys  []string
}

var _ port.CapacitySourceProtectionReader = (*CapacityGuard)(nil)
var _ port.CapacityNamespaceProtectionReader = (*CapacityNamespaceGuard)(nil)

func newCapacityGuard(observer, probe *PermissionClient, namespace, account cfg.NamespaceRef, name string, admins []cfg.KubernetesActor, status []string, pin GuardPin, policy *admission.ValidatingAdmissionPolicy, binding *admission.ValidatingAdmissionPolicyBinding, plan any) (*capacityGuard, error) {
	if observer == nil || probe == nil || observer == probe || observer.clusterID != probe.clusterID || observer.control != namespace || probe.control != namespace || !identity.Text(pin.PolicyUID, 64) || !identity.Text(pin.BindingUID, 64) || !identity.Text(pin.BindingResourceVersion, 128) || pin.PolicyGeneration < 1 || pin.PolicyGeneration > 2147483647 {
		return nil, cfg.ErrInvalid
	}
	normalizePermissionPolicy(&policy.Spec)
	bound, err := json.Marshal(struct {
		Format, ClusterID string
		Plan              any
		Pin               GuardPin
	}{"capacity-protection/v1", observer.clusterID, plan, pin})
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	return &capacityGuard{observer: observer, probe: probe, namespace: namespace, account: account, name: name, administrators: slices.Clone(admins), statusUsers: slices.Clone(status), pin: pin, policy: policy.Spec, binding: binding.Spec, digest: sha256.Sum256(bound)}, nil
}
func NewCapacityGuard(observer, probe *PermissionClient, plan cfg.CapacityAdministration, pin GuardPin) (*CapacityGuard, error) {
	p, b, err := CapacityAdmission(plan)
	if err != nil {
		return nil, err
	}
	g, err := newCapacityGuard(observer, probe, plan.ControlNamespace, plan.ProbeAccount, plan.Name, plan.Administrators, plan.StatusUsers, pin, p, b, plan)
	if err != nil {
		return nil, err
	}
	return &CapacityGuard{guard: g}, nil
}
func NewCapacityNamespaceGuard(observer, probe *PermissionClient, plan cfg.CapacityNamespaceAdministration, pin GuardPin) (*CapacityNamespaceGuard, error) {
	p, b, err := CapacityNamespaceAdmission(plan)
	if err != nil {
		return nil, err
	}
	g, err := newCapacityGuard(observer, probe, plan.ProbeNamespace, plan.ProbeAccount, plan.Name, plan.Administrators, nil, pin, p, b, plan)
	if err != nil {
		return nil, err
	}
	return &CapacityNamespaceGuard{guard: g, keys: slices.Clone(plan.Keys)}, nil
}
func (g *capacityGuard) accountCurrent(ctx context.Context) error {
	raw, err := g.observer.raw(ctx, "/api/v1/namespaces/"+g.namespace.Name+"/serviceaccounts/"+g.account.Name, nil)
	var a core.ServiceAccount
	if err != nil || strictGuardJSON(raw, &a) != nil || a.APIVersion != "v1" || a.Kind != "ServiceAccount" || a.Namespace != g.namespace.Name || a.Name != g.account.Name || string(a.UID) != g.account.UID || a.DeletionTimestamp != nil {
		return cfg.ErrChanged
	}
	return nil
}
func (g *capacityGuard) probeIdentity(ctx context.Context) error {
	if err := g.accountCurrent(ctx); err != nil {
		return err
	}
	raw, err := g.probe.proofPost(ctx, "/apis/authentication.k8s.io/v1/selfsubjectreviews", authentication.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}}, nil)
	var who authentication.SelfSubjectReview
	if err != nil || strictGuardJSON(raw, &who) != nil || who.Status.UserInfo.Username != "system:serviceaccount:"+g.namespace.Name+":"+g.account.Name || who.Status.UserInfo.UID != g.account.UID || !identity.Strings(who.Status.UserInfo.Groups, 256, 256) || slices.Contains(g.statusUsers, who.Status.UserInfo.Username) {
		return cfg.ErrUnavailable
	}
	for _, a := range g.administrators {
		if actorMatches(a, who.Status.UserInfo) {
			return cfg.ErrUnavailable
		}
	}
	return nil
}
func (g *capacityGuard) probeAllowed(ctx context.Context, verb, group, resource, namespace, name string) error {
	review := authorization.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Spec: authorization.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorization.ResourceAttributes{Verb: verb, Group: group, Version: "v1alpha1", Resource: resource, Namespace: namespace, Name: name}}}
	if group == "" {
		review.Spec.ResourceAttributes.Version = "v1"
	}
	raw, err := g.probe.proofPost(ctx, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review, nil)
	var a authorization.SelfSubjectAccessReview
	if err != nil || strictGuardJSON(raw, &a) != nil || !a.Status.Allowed || a.Status.Denied || a.Status.EvaluationError != "" {
		return cfg.ErrUnavailable
	}
	return nil
}
func capacityExactDenial(err error, policy, group, resource, message string) error {
	var status apierrors.APIStatus
	if (!apierrors.IsInvalid(err) && !apierrors.IsForbidden(err)) || !errors.As(err, &status) {
		return cfg.ErrUnavailable
	}
	s := status.Status()
	if s.Details == nil || s.Details.Group != group || s.Details.Kind != resource || len(s.Details.Causes) > 8 {
		return cfg.ErrUnavailable
	}
	expected := "ValidatingAdmissionPolicy '" + policy + "' with binding '" + policy + "' denied request: " + message
	for _, cause := range s.Details.Causes {
		if cause.Message == expected {
			return nil
		}
	}
	return cfg.ErrUnavailable
}
func (g *capacityGuard) current(ctx context.Context, prove func(context.Context) error) (time.Time, time.Time, error) {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return time.Time{}, time.Time{}, cfg.ErrUnavailable
	}
	start := g.observer.now()
	until := start.Add(port.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	ns, err := g.observer.namespace(call, g.namespace)
	if err != nil || ns.Deleting {
		return time.Time{}, time.Time{}, cfg.ErrChanged
	}
	before, err := checkAdmissionGuard(call, g.observer, g.name, g.pin, g.policy, g.binding)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err = g.probeIdentity(call); err != nil {
		return time.Time{}, time.Time{}, err
	}
	if err = prove(call); err != nil {
		return time.Time{}, time.Time{}, err
	}
	after, err := checkAdmissionGuard(call, g.observer, g.name, g.pin, g.policy, g.binding)
	if err != nil || after != before {
		return time.Time{}, time.Time{}, cfg.ErrChanged
	}
	if err = g.accountCurrent(call); err != nil {
		return time.Time{}, time.Time{}, err
	}
	ns, err = g.observer.namespace(call, g.namespace)
	if err != nil || ns.Deleting {
		return time.Time{}, time.Time{}, cfg.ErrChanged
	}
	if call.Err() != nil || !identity.Fresh(start, until, g.observer.now(), port.CapacitySourceInterval) {
		return time.Time{}, time.Time{}, cfg.ErrUnavailable
	}
	return start, until, nil
}

func (g *CapacityGuard) CapacityProtection(ctx context.Context) (port.CapacitySourceProtection, error) {
	var out port.CapacitySourceProtection
	if g == nil || g.guard == nil {
		return out, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx, func(call context.Context) error {
		for _, kind := range []string{"EvidenceStoragePool", "EvidenceBudgetPolicy"} {
			resource := "evidencestoragepools"
			if kind == "EvidenceBudgetPolicy" {
				resource = "evidencebudgetpolicies"
			}
			if err := s.probeAllowed(call, "create", "asservat.io", resource, s.namespace.Name, ""); err != nil {
				return err
			}
			body := map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": kind, "metadata": map[string]any{"generateName": "asservat-capacity-probe-", "namespace": s.namespace.Name}, "spec": capacityProbeSpec(kind, s.observer.clusterID)}
			_, err := s.probe.proofPost(call, "/apis/asservat.io/v1alpha1/namespaces/"+s.namespace.Name+"/"+resource, body, map[string]string{"dryRun": "All", "fieldValidation": "Strict"})
			if err = capacityExactDenial(err, s.name, "asservat.io", resource, capacitySourceDenial); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	return port.CapacitySourceProtection{ClusterID: s.observer.clusterID, ControlNamespaceUID: s.namespace.UID, Digest: s.digest, ObservedAt: start, FreshUntil: until}, nil
}

func (g *CapacityNamespaceGuard) CapacityNamespaceProtection(ctx context.Context) (port.CapacityNamespaceProtection, error) {
	var out port.CapacityNamespaceProtection
	if g == nil || g.guard == nil {
		return out, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx, func(call context.Context) error {
		if err := s.probeAllowed(call, "update", "", "namespaces", "", s.namespace.Name); err != nil {
			return err
		}
		raw, err := s.observer.raw(call, "/api/v1/namespaces/"+s.namespace.Name, nil)
		var ns core.Namespace
		if err != nil || strictGuardJSON(raw, &ns) != nil || ns.APIVersion != "v1" || ns.Kind != "Namespace" || ns.Name != s.namespace.Name || string(ns.UID) != s.namespace.UID || ns.DeletionTimestamp != nil || !identity.Text(ns.ResourceVersion, 128) {
			return cfg.ErrChanged
		}
		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		key, value := g.keys[0], "asservat-capacity-probe"
		if ns.Labels[key] == value {
			value = "asservat-capacity-probe-other"
		}
		ns.Labels[key] = value
		body, err := json.Marshal(ns)
		if err != nil {
			return cfg.ErrUnavailable
		}
		response := s.probe.api.Put().AbsPath("/api/v1/namespaces/"+ns.Name).MaxRetries(0).Param("dryRun", "All").Param("fieldValidation", "Strict").Body(body).Do(call)
		raw, err = response.Raw()
		if permissionJSON(raw, permissionPageBytes, 131072) != nil {
			return cfg.ErrUnavailable
		}
		return capacityExactDenial(response.Error(), s.name, "", "namespaces", capacityNamespaceDenial)
	})
	if err != nil {
		return out, err
	}
	return port.CapacityNamespaceProtection{ClusterID: s.observer.clusterID, Digest: s.digest, Keys: slices.Clone(g.keys), ObservedAt: start, FreshUntil: until}, nil
}
