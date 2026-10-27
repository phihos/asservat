package targets

import (
	"slices"

	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// AccessReviewRequest asks the target cluster's connector whether one
// authenticated human principal, mapped through the connector's own
// administrator-configured identity mapping, passes one accepted
// decision-time source's check on one exact Pod (REQ-PER-004, ADR-245). The
// hub sends the verified Asservat principal, never a Kubernetes user name:
// clients cannot choose the reviewed Kubernetes identity.
type AccessReviewRequest struct {
	Target    Request
	Source    AccessReviewSource
	Principal AccessReviewPrincipal
}

// AccessReviewSource is the part of an accepted source the connector applies.
type AccessReviewSource struct {
	UID, Type, Check, IdentityMapping string
	NamespaceSelector                 map[string]string `json:",omitempty"`
	ExcludedNamespaces                []string          `json:",omitempty"`
}

// AccessReviewPrincipal is the request's current authenticated identity:
// issuer, stable subject and current stable group IDs, never stored groups.
type AccessReviewPrincipal struct {
	Issuer, Subject string
	Groups          []string `json:",omitempty"`
}

// Closed review outcomes. Only AccessAllowed grants; every other outcome
// denies the source for this request.
const (
	AccessAllowed            = "Allowed"
	AccessDenied             = "Denied"
	AccessOutsideSource      = "OutsideSource"
	AccessTargetChanged      = "TargetChanged"
	AccessMappingUnsupported = "MappingUnsupported"
)

// AccessReviewAnswer is the connector's closed decision. It carries no
// Kubernetes user name, group or authorizer reason text.
type AccessReviewAnswer struct {
	SourceUID string
	Outcome   string
}

func (s AccessReviewSource) Valid() bool {
	if !identity.Text(s.UID, 64) || !identity.Text(s.IdentityMapping, 63) || len(s.NamespaceSelector) > 16 || !identity.Strings(s.ExcludedNamespaces, 64, 63) {
		return false
	}
	switch s.Type {
	case configuration.SourceKubernetesExec:
		if s.Check != configuration.ReviewPodExec {
			return false
		}
	case configuration.SourceKubernetesAccessReview:
		if !slices.Contains([]string{configuration.ReviewNamespaceCaptureCreate, configuration.ReviewWorkloadGet, configuration.ReviewWorkloadPatch, configuration.ReviewWorkloadUpdate}, s.Check) {
			return false
		}
	default:
		return false
	}
	for k, v := range s.NamespaceSelector {
		if !identity.Text(k, 317) || !identity.Text(v, 63) {
			return false
		}
	}
	return true
}

func (r AccessReviewRequest) Valid() bool {
	p := r.Principal
	return r.Target.Valid() && r.Source.Valid() && identity.Text(p.Issuer, 2048) && identity.Text(p.Subject, 256) && identity.Strings(p.Groups, 256, 256)
}

func (a AccessReviewAnswer) Valid(r AccessReviewRequest) bool {
	return a.SourceUID == r.Source.UID && slices.Contains([]string{AccessAllowed, AccessDenied, AccessOutsideSource, AccessTargetChanged, AccessMappingUnsupported}, a.Outcome)
}

// ReviewRequest builds the connector request of one accepted source.
func ReviewRequest(s configuration.ReviewSource, target Request, issuer, subject string, groups []string) AccessReviewRequest {
	return AccessReviewRequest{Target: target, Source: AccessReviewSource{UID: s.Resource.UID, Type: s.Type, Check: s.Check, IdentityMapping: s.IdentityMappingRef, NamespaceSelector: s.NamespaceSelector, ExcludedNamespaces: s.ExcludedNamespaces},
		Principal: AccessReviewPrincipal{Issuer: issuer, Subject: subject, Groups: slices.Clone(groups)}}
}
