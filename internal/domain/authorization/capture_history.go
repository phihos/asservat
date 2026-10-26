package authorization

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureHistoryEligibility decides whether one accepted capture appears in
// the caller's capture history (ADR-236, REQ-HIS-003). The caller needs
// current ordinary read rights on the capture's target and is either the
// original requester (issuer, subject and kind; any client) or holds a
// current assignment that is part of the capture's retained audience. A newly
// granted assignment, such as a new owner of a recreated or transferred
// workload, is not in an older capture's audience and sees nothing. A share
// grants no target assignment and therefore no history.
func CaptureHistoryEligibility(i identity.Identity, p Projection, target Target, creator identity.Principal, retained []artifact.AudienceAssignment, now time.Time) Result {
	if !creator.Valid() {
		return Result{Reason: "InvalidRequester"}
	}
	r := ScopeEligibility(i, p, ReadApproved, target, now)
	if !r.Eligible {
		return r
	}
	if i.Principal.Issuer == creator.Issuer && i.Principal.Subject == creator.Subject && i.Principal.Kind == creator.Kind {
		return r
	}
	var matched []artifact.AudienceAssignment
	for _, a := range r.ContributingAssignments {
		if slices.Contains(retained, a) {
			matched = append(matched, a)
		}
	}
	if len(matched) == 0 {
		return Result{Reason: "NoHistoryEntitlement"}
	}
	r.ContributingAssignments = matched
	return r
}
