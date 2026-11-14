package configuration

import (
	"slices"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Decision-time PermissionSource types (REQ-PER-004, ADR-245). They name no
// subject: the target cluster's connector reviews each authenticated human
// principal for each Pod when a request needs it.
const (
	SourceKubernetesExec         = "kubernetesExec"
	SourceKubernetesAccessReview = "kubernetesAccessReview"
)

// Review checks. ReviewPodExec is `create pods/exec` on the exact Pod; the
// others are the kubernetesAccessReview checks of the source schema.
const (
	ReviewPodExec                = "podExec"
	ReviewNamespaceCaptureCreate = "namespaceCaptureCreate"
	ReviewWorkloadGet            = "workloadGet"
	ReviewWorkloadPatch          = "workloadPatch"
	ReviewWorkloadUpdate         = "workloadUpdate"
)

// ReviewDecisionAge is how long an allowed review is reused
// (identity.AuthorityRecheckInterval, ADR-311).
const ReviewDecisionAge = identity.AuthorityRecheckInterval

// ReviewSource is the accepted form of one decision-time source. It is
// configuration, not a grant: a principal gains the role on one Pod only
// through a fresh allowed review recorded for that Pod.
type ReviewSource struct {
	Resource           Resource
	Type               string
	ClusterID, Role    string
	Check              string
	NamespaceSelector  map[string]string `json:",omitempty"`
	ExcludedNamespaces []string          `json:",omitempty"`
	IdentityMappingRef string
	ParityReviewRef    string `json:",omitempty"`
}

// SameAuthority reports whether two accepted versions decide whose access a
// review confers in the same way: type, cluster, role, check and identity
// mapping (the parity mode is fixed). Selector, exclusions and lifetime are
// applied afresh by every review, so a change of only those keeps the
// per-principal assignments.
func (r ReviewSource) SameAuthority(o ReviewSource) bool {
	return r.Type == o.Type && r.ClusterID == o.ClusterID && r.Role == o.Role && r.Check == o.Check && r.IdentityMappingRef == o.IdentityMappingRef
}

// ReviewSourceFor returns the accepted form of s, or why it grants nothing.
// Only the noAdditionalRestrictions parity mode is supported: no qualified
// exec-restriction adapter exists, so a qualifiedAdapter source is
// SourceUnsupported (REQ-PER-004 requires the adapter before enabling it).
func ReviewSourceFor(s Source) (ReviewSource, string) {
	if s.Type != SourceKubernetesExec && s.Type != SourceKubernetesAccessReview {
		return ReviewSource{}, SourceUnsupported
	}
	if !s.Enabled || s.Resource.Deleting {
		return ReviewSource{}, SourceDisabled
	}
	check := s.AccessReviewCheck
	switch s.Type {
	case SourceKubernetesExec:
		if check != "" || s.Role != "workload-maintainer" {
			return ReviewSource{}, SourceUnsupported
		}
		check = ReviewPodExec
	default:
		// An access review may map to any role (REQ-PER-004).
		if !slices.Contains([]string{ReviewNamespaceCaptureCreate, ReviewWorkloadGet, ReviewWorkloadPatch, ReviewWorkloadUpdate}, check) || !slices.Contains(Roles, s.Role) {
			return ReviewSource{}, SourceUnsupported
		}
	}
	p := s.AdmissionParity
	if p.Mode != "noAdditionalRestrictions" || p.AdapterRef != "" || !identity.Text(s.IdentityMappingRef, 63) || !authorization.UUID(s.ClusterID) {
		return ReviewSource{}, SourceUnsupported
	}
	r := ReviewSource{Resource: s.Resource, Type: s.Type, ClusterID: s.ClusterID, Role: s.Role, Check: check, IdentityMappingRef: s.IdentityMappingRef, ParityReviewRef: p.ReviewRef}
	if len(s.NamespaceSelector) > 0 {
		r.NamespaceSelector = map[string]string{}
		for k, v := range s.NamespaceSelector {
			r.NamespaceSelector[k] = v
		}
	}
	r.ExcludedNamespaces = slices.Sorted(slices.Values(s.ExcludedNamespaces))
	return r, ""
}

// Valid checks an accepted review source as a batch carries it.
func (r ReviewSource) Valid() bool {
	res := r.Resource
	if res.Kind != "PermissionSource" || !identity.Text(res.UID, 64) || !identity.Text(res.ResourceVersion, 128) || res.Generation < 1 || res.Generation > 2147483647 || res.SpecDigest == (artifact.Digest{}) || res.Deleting {
		return false
	}
	want := Source{Resource: res, Enabled: true, Type: r.Type, ClusterID: r.ClusterID, Role: r.Role, NamespaceSelector: r.NamespaceSelector, ExcludedNamespaces: r.ExcludedNamespaces, IdentityMappingRef: r.IdentityMappingRef, AdmissionParity: AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: r.ParityReviewRef}}
	if r.Type == SourceKubernetesAccessReview {
		want.AccessReviewCheck = r.Check
	}
	again, reason := ReviewSourceFor(want)
	if reason != "" || !again.SameAuthority(r) || again.ParityReviewRef != r.ParityReviewRef || !slices.Equal(again.ExcludedNamespaces, r.ExcludedNamespaces) {
		return false
	}
	for k, v := range r.NamespaceSelector {
		if !identity.Text(k, 317) || !identity.Text(v, 63) {
			return false
		}
	}
	return identity.Strings(r.ExcludedNamespaces, len(r.ExcludedNamespaces), 63)
}

// ReviewSources selects the accepted decision-time sources of a source list:
// valid kubernetesExec/kubernetesAccessReview sources in UID order.
func ReviewSources(sources []Source) []ReviewSource {
	sorted := slices.Clone(sources)
	slices.SortFunc(sorted, func(a, b Source) int { return strings.Compare(a.Resource.UID, b.Resource.UID) })
	var out []ReviewSource
	for _, s := range sorted {
		if r, reason := ReviewSourceFor(s); reason == "" {
			out = append(out, r)
		}
	}
	return out
}

// ReviewDecisionUntil is the end of a positive review decided at decidedAt.
func (r ReviewSource) ReviewDecisionUntil(decidedAt time.Time) time.Time {
	return decidedAt.Add(ReviewDecisionAge)
}

// EquivalentReview reports whether an accepted review source version keeps
// the per-principal assignments of the previous one: same UID and authority, and either the same generation and spec or exactly one spec
// transition (as for any PermissionSource, ADR-242). A generation jump may
// hide an A -> B -> A change and retires them.
func EquivalentReview(old, next ReviewSource) bool {
	if old.Resource.UID != next.Resource.UID || !old.SameAuthority(next) {
		return false
	}
	switch next.Resource.Generation {
	case old.Resource.Generation:
		return old.Resource.SpecDigest == next.Resource.SpecDigest
	case old.Resource.Generation + 1:
		return true
	}
	return false
}
