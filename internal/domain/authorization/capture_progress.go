package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// CaptureProgressEligibility permits the original requester with current
// ordinary target read rights, or a current workload maintainer. Client changes
// do not create another human; issuer/subject/kind still match exactly. A share
// supplies no target assignment, and operator status is not an inferred bypass.
func CaptureProgressEligibility(i identity.Identity, p Projection, target Target, creator identity.Principal, now time.Time) Result {
	if !creator.Valid() {
		return Result{Reason: "InvalidRequester"}
	}
	r := ScopeEligibility(i, p, ReadApproved, target, now)
	if !r.Eligible {
		return r
	}
	requester := i.Principal.Issuer == creator.Issuer && i.Principal.Subject == creator.Subject && i.Principal.Kind == creator.Kind
	if requester {
		return r
	}
	for _, a := range r.ContributingAssignments {
		if a.Role == "workload-maintainer" {
			return r
		}
	}
	return Result{Reason: "NoCaptureEntitlement"}
}
