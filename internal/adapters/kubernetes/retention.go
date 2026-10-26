package kubernetes

import (
	wire "asservat.local/asservat/api/v1alpha1"
	configuration "asservat.local/asservat/internal/application/configuration"
	port "asservat.local/asservat/internal/application/privacy"
	configvalue "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"slices"
	"time"
)

type RetentionClient struct {
	client *PermissionClient
	hub    bool
}

var _ port.PolicySnapshotReader = (*RetentionClient)(nil)
var _ configuration.RetentionListReader = (*RetentionClient)(nil)

func NewRetentionClient(client *PermissionClient, hub bool) (*RetentionClient, error) {
	if client == nil {
		return nil, value.ErrInvalid
	}
	return &RetentionClient{client, hub}, nil
}
func (c *RetentionClient) RetentionSnapshot(ctx context.Context) (value.PolicySnapshot, error) {
	l, err := c.RetentionPolicyList(ctx)
	return l.Snapshot, err
}
func (c *RetentionClient) policy(o permissionObject, ref configvalue.Resource) (value.ScopedPolicy, error) {
	return retentionPolicy(c.client.validator, c.hub, o, ref)
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
func (c *RetentionClient) RetentionPolicyList(ctx context.Context) (configuration.PolicyList, error) {
	var out configuration.PolicyList
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := c.client.now()
	ns, err := c.client.namespace(ctx, c.client.control)
	if err != nil || ns.Deleting {
		return out, value.ErrUnavailable
	}
	budget := permissionTotalBytes
	rv, objects, refs, err := c.client.list(ctx, "EvidenceRetentionPolicy", "evidenceretentionpolicies", start, &budget)
	if err != nil {
		return out, value.ErrUnavailable
	}
	out.ResourceVersion = rv
	out.Versions = map[string]string{}
	out.Snapshot = value.PolicySnapshot{SourceClusterID: c.client.clusterID, ControlNamespaceUID: c.client.control.UID, Hub: c.hub, ObservedAt: start, FreshUntil: start.Add(5 * time.Second)}
	for i, o := range objects {
		ref := refs[i]
		if ref.Deleting {
			return configuration.PolicyList{}, value.ErrUnavailable
		}
		p, err := c.policy(o, ref)
		if err != nil {
			return configuration.PolicyList{}, err
		}
		out.Snapshot.Policies = append(out.Snapshot.Policies, p)
		out.Versions[ref.UID] = ref.ResourceVersion
	}
	slices.SortFunc(out.Snapshot.Policies, func(a, b value.ScopedPolicy) int {
		if a.Policy.Revision.UID < b.Policy.Revision.UID {
			return -1
		}
		if a.Policy.Revision.UID > b.Policy.Revision.UID {
			return 1
		}
		return 0
	})
	out.Snapshot.Revision = identity.Revision{UID: out.Snapshot.ControlNamespaceUID, Generation: 1, Digest: configuration.RetentionSnapshotDigest(out.Snapshot)}
	ns, err = c.client.namespace(ctx, c.client.control)
	if err != nil || ns.Deleting || c.client.current(ctx, start, 5*time.Second) != nil || !out.Snapshot.Valid(c.client.now()) {
		return configuration.PolicyList{}, value.ErrUnavailable
	}
	return out, nil
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
