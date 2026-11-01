package privacy

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// HistoricalSourcePolicies matches only relationships whose history is known:
// original/later-bound policy UIDs, cluster scope and unscoped policies. Newly
// encountered label selectors require a qualified historical metadata source;
// this initial context catch-up must fail rather than infer those labels today.
// The caller must load s from an independently accepted immutable checkpoint.
func HistoricalSourcePolicies(s PolicySnapshot, r RetainedArtifact) ([]Policy, error) {
	if !s.Valid(s.ObservedAt) || !r.Valid() {
		return nil, ErrInvalid
	}
	if !s.Hub && s.SourceClusterID != r.Input.Target.ClusterID {
		return nil, nil
	}
	origins := map[string]artifact.RetentionRule{}
	for _, p := range r.OriginPolicies {
		origins[p.UID] = p
	}
	policies := []Policy{}
	for _, p := range s.Policies {
		old, bound := origins[p.Policy.Revision.UID]
		if bound {
			if p.Policy.Revision.Generation < old.Generation || (p.Policy.Revision.Generation == old.Generation && p.Policy.Revision.Digest != old.Digest) {
				return nil, ErrUnavailable
			}
		} else {
			if len(p.Scope.ClusterIDs) > 0 && !slices.Contains(p.Scope.ClusterIDs, r.Input.Target.ClusterID) {
				continue
			}
			if len(p.Scope.NamespaceLabels) > 0 || len(p.Scope.WorkloadLabels) > 0 {
				return nil, ErrUnavailable
			}
		}
		policy := p.Policy
		if r.Input.ControlKind == "case-metadata" {
			policy = CaseMetadataPolicy(p)
		}
		policies = append(policies, policy)
	}
	if len(policies) > 64 {
		return nil, ErrUnavailable
	}
	return policies, nil
}

// ApplyRetainedObligation applies a historical source subset to existing dates.
// It has no freshness, baseline-completeness or acquisition/disclosure grant:
// only the complete current resolver can authorize a new collection. Defaults
// never reselect the original request. Empty applicable sets preserve all dates.
func ApplyRetainedObligation(r RetainedArtifact, policies []Policy) (Deadlines, []artifact.RetentionRule, error) {
	if !r.Valid() || len(policies) > 64 {
		return Deadlines{}, nil, ErrInvalid
	}
	if len(policies) == 0 {
		return r.Effective, nil, nil
	}
	maximum, budget := MaxAgeSeconds, int64(0)
	refs := make([]artifact.RetentionRule, 0, len(policies))
	seen := map[string]bool{}
	for _, p := range policies {
		if !p.Valid() || seen[p.Revision.UID] {
			return Deadlines{}, nil, ErrInvalid
		}
		seen[p.Revision.UID] = true
		maximum = min(maximum, p.MaximumSeconds)
		budget = max(budget, p.DeletionBudgetSeconds)
		for _, rule := range p.Rules {
			if matchesClass(rule.PrivacyClasses, r.Input.PrivacyClass) && (len(rule.EvidenceTypes) == 0 || r.Input.EvidenceType == "other" || slices.Contains(rule.EvidenceTypes, r.Input.EvidenceType)) {
				maximum = min(maximum, rule.MaxAgeSeconds)
			}
		}
		refs = append(refs, artifact.RetentionRule{UID: p.Revision.UID, Generation: p.Revision.Generation, Digest: p.Revision.Digest})
	}
	if _, err := MergePolicyOrigins(r.OriginPolicies, refs); err != nil {
		return Deadlines{}, nil, err
	}
	out := r.Effective
	out.DeleteBy = identity.Earlier(out.DeleteBy, out.AnchorAt.Add(time.Duration(maximum)*time.Second))
	read := out.DeleteBy.Add(-time.Duration(budget) * time.Second)
	if read.Before(out.AnchorAt) {
		read = out.AnchorAt
	}
	out.ExpiresAt = identity.Earlier(out.ExpiresAt, read)
	slices.SortFunc(refs, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	if !out.ValidRetained() {
		return Deadlines{}, nil, ErrInvalid
	}
	return out, refs, nil
}

type RetentionCatchupPage struct {
	CheckpointID       string
	Sequence           int64
	Visited, Shortened int
	Complete           bool
	Idle               bool
}
