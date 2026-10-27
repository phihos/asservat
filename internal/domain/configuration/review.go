package configuration

import (
	"slices"
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

// MaxReviewSourcesPerCluster bounds the SubjectAccessReviews one request makes
// on one cluster. Further sources of that cluster (in UID order) grant nothing.
const MaxReviewSourcesPerCluster = 4

// MaxDecisionAge is the REQ-PER-006 maximum positive source decision age.
const MaxDecisionAge = 60 * time.Second

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
	MaxDecisionAge     time.Duration
	MaxNamespaces      int
	IdentityMappingRef string
	ParityReviewRef    string
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
		if !slices.Contains([]string{ReviewNamespaceCaptureCreate, ReviewWorkloadGet, ReviewWorkloadPatch, ReviewWorkloadUpdate}, check) || s.Role != "evidence-reader" && s.Role != "workload-maintainer" {
			return ReviewSource{}, SourceUnsupported
		}
	}
	p := s.AdmissionParity
	if p.Mode != "noAdditionalRestrictions" || p.AdapterRef != "" || !identity.Text(p.ReviewRef, 256) || !identity.Text(s.IdentityMappingRef, 63) ||
		!authorization.UUID(s.ClusterID) || s.MaxDecisionAge < time.Second || s.MaxDecisionAge > MaxDecisionAge || s.MaxNamespaces < 1 || s.MaxNamespaces > 1000 || len(s.ExcludedNamespaces) > 64 || len(s.NamespaceSelector) > 16 {
		return ReviewSource{}, SourceUnsupported
	}
	r := ReviewSource{Resource: s.Resource, Type: s.Type, ClusterID: s.ClusterID, Role: s.Role, Check: check, MaxDecisionAge: s.MaxDecisionAge, MaxNamespaces: s.MaxNamespaces, IdentityMappingRef: s.IdentityMappingRef, ParityReviewRef: p.ReviewRef}
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
	want := Source{Resource: res, Enabled: true, Type: r.Type, ClusterID: r.ClusterID, Role: r.Role, NamespaceSelector: r.NamespaceSelector, ExcludedNamespaces: r.ExcludedNamespaces, MaxDecisionAge: r.MaxDecisionAge, MaxNamespaces: r.MaxNamespaces, IdentityMappingRef: r.IdentityMappingRef, AdmissionParity: AdmissionParity{Mode: "noAdditionalRestrictions", ReviewRef: r.ParityReviewRef}}
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
	return identity.Strings(r.ExcludedNamespaces, 64, 63)
}

// ReviewSources selects the accepted decision-time sources of a source list:
// valid kubernetesExec/kubernetesAccessReview sources, at most
// MaxReviewSourcesPerCluster per cluster in UID order.
func ReviewSources(sources []Source) []ReviewSource {
	sorted := slices.Clone(sources)
	slices.SortFunc(sorted, func(a, b Source) int {
		switch {
		case a.Resource.UID < b.Resource.UID:
			return -1
		case a.Resource.UID > b.Resource.UID:
			return 1
		}
		return 0
	})
	var out []ReviewSource
	per := map[string]int{}
	for _, s := range sorted {
		r, reason := ReviewSourceFor(s)
		if reason != "" || per[r.ClusterID] >= MaxReviewSourcesPerCluster {
			continue
		}
		per[r.ClusterID]++
		out = append(out, r)
	}
	return out
}

// ReviewDecisionUntil is the end of a positive review decided at decidedAt:
// the source's maxDecisionAgeSeconds, never more than MaxDecisionAge.
func (r ReviewSource) ReviewDecisionUntil(decidedAt time.Time) time.Time {
	age := r.MaxDecisionAge
	if age > MaxDecisionAge || age <= 0 {
		age = MaxDecisionAge
	}
	return decidedAt.Add(age)
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
