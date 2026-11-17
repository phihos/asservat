package kubernetes

import (
	"context"
	"slices"
	"strings"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	port "asservat.local/asservat/internal/application/privacy"
	configvalue "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// RetentionClient lists and watches the EvidenceRetentionPolicy objects of
// the hub control namespace.
type RetentionClient struct{ client *PermissionClient }

var _ port.RetentionSource = (*RetentionClient)(nil)

func NewRetentionClient(client *PermissionClient) (*RetentionClient, error) {
	if client == nil {
		return nil, value.ErrInvalid
	}
	return &RetentionClient{client}, nil
}
// policy decodes one observed policy; one the domain rejects (for example a
// deletion budget not below its maximum) is invalid here, not at storage.
func (c *RetentionClient) policy(o permissionObject, ref configvalue.Resource) (value.ScopedPolicy, error) {
	p, err := retentionPolicy(c.client.validator, true, o, ref)
	if err == nil && !p.Valid() {
		return value.ScopedPolicy{}, value.ErrInvalid
	}
	return p, err
}

// retentionPolicy decodes one EvidenceRetentionPolicy spec with the embedded
// schema; observed objects and ADR-240 proposals share it.
func retentionPolicy(v *permissionValidator, hub bool, o permissionObject, ref configvalue.Resource) (value.ScopedPolicy, error) {
	var out value.ScopedPolicy
	var spec wire.RetentionPolicySpec
	digest, err := decodePermissionSpec(o.Spec, v.retentionSchema, &spec)
	if err != nil {
		return out, value.ErrUnavailable
	}
	scope := value.PolicyScope{ClusterIDs: spec.Scope.ClusterIDs}
	if spec.Scope.NamespaceSelector != nil {
		scope.NamespaceLabels = spec.Scope.NamespaceSelector.MatchLabels
	}
	if spec.Scope.WorkloadSelector != nil {
		scope.WorkloadLabels = spec.Scope.WorkloadSelector.MatchLabels
	}
	if !selectorValid(scope.NamespaceLabels) || !selectorValid(scope.WorkloadLabels) {
		return out, value.ErrInvalid
	}
	policy := value.Policy{Revision: identity.Revision{UID: ref.UID, Generation: ref.Generation, Digest: digest}, Baseline: hub && scope.Empty(), PurposeRef: spec.PurposeRef, DefaultSeconds: spec.Defaults.EvidenceSeconds, MaximumSeconds: spec.Maxima.EvidenceSeconds, DeletionBudgetSeconds: spec.DeletionBudgetSeconds}
	for _, r := range spec.Rules {
		policy.Rules = append(policy.Rules, value.Rule{Name: r.Name, PrivacyClasses: r.PrivacyClasses, EvidenceTypes: r.EvidenceTypes, MaxAgeSeconds: r.MaxAgeSeconds})
	}
	out = value.ScopedPolicy{Name: ref.Name, Policy: policy, Scope: scope, CaseDefaultSeconds: spec.Defaults.CaseMetadataSeconds, CaseMaximumSeconds: spec.Maxima.CaseMetadataSeconds, AuditDefaultSeconds: spec.Defaults.AuditMetadataSeconds, AuditMaximumSeconds: spec.Maxima.AuditMetadataSeconds, LegalExceptions: spec.LegalExceptions}
	return out, nil
}

// ListRetentionPolicies returns the current policies and the list's
// resourceVersion to watch from.
func (c *RetentionClient) ListRetentionPolicies(ctx context.Context) ([]value.ScopedPolicy, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rv, objects, refs, _, err := c.client.list(ctx, "EvidenceRetentionPolicy", "evidenceretentionpolicies", c.client.now())
	if err != nil {
		return nil, "", value.ErrUnavailable
	}
	out := make([]value.ScopedPolicy, 0, len(objects))
	for i, o := range objects {
		p, err := c.policy(o, refs[i])
		if err != nil {
			return nil, "", err
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b value.ScopedPolicy) int {
		return strings.Compare(a.Policy.Revision.UID, b.Policy.Revision.UID)
	})
	return out, rv, nil
}

// RetentionPolicySpecDecoder decodes a proposed EvidenceRetentionPolicy spec
// with the same embedded schema and checks as observed policies (ADR-240
// impact preview). The result carries the canonical spec digest; it is never
// an observed or accepted policy.
type RetentionPolicySpecDecoder struct{ validator *permissionValidator }

func NewRetentionPolicySpecDecoder() (*RetentionPolicySpecDecoder, error) {
	v, err := newPermissionValidator()
	if err != nil {
		return nil, err
	}
	return &RetentionPolicySpecDecoder{v}, nil
}

// DecodeRetentionPolicySpec decodes spec for the hub source (hub) or a local
// source; an empty hub scope is the installation baseline.
func (d *RetentionPolicySpecDecoder) DecodeRetentionPolicySpec(spec []byte, hub bool) (value.ScopedPolicy, error) {
	if d == nil || d.validator == nil {
		return value.ScopedPolicy{}, value.ErrUnavailable
	}
	p, err := retentionPolicy(d.validator, hub, permissionObject{Spec: spec}, configvalue.Resource{Kind: "EvidenceRetentionPolicy"})
	if err != nil {
		return value.ScopedPolicy{}, value.ErrInvalid
	}
	return p, nil
}
