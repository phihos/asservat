package authorization

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureEligibility separates the requesting actor's eligibility from the full
// immutable default audience. It remains input to admission, not an execution
// capability. Owner assignments retain their original independent identities.
type CaptureEligibility struct {
	Result
	Target Target
	// VerifiedIdentity is supplied only by the identity resolver. Transactions
	// can reevaluate the current SQL projection after locks without carrying a
	// bearer token or doing remote identity I/O while holding locks.
	VerifiedIdentity identity.Identity
	DefaultAudience  []artifact.AudienceAssignment
}

func ContextEligibility(i identity.Identity, p Projection, target Target, now time.Time) CaptureEligibility {
	result := Evaluate(i, p, CollectContext, target, nil, now)
	if !result.Eligible {
		return CaptureEligibility{Result: result}
	}
	audience, until, reason := defaultAudience(p, &i, now)
	if reason != "" {
		return CaptureEligibility{Result: Result{Reason: reason}}
	}
	result.ValidUntil = identity.Earlier(result.ValidUntil, until)
	return CaptureEligibility{Result: result, Target: target, VerifiedIdentity: i, DefaultAudience: audience}
}

// defaultAudience is the complete default evidence audience of a new capture:
// every current, non-denied assignment that may read approved evidence. It
// never adds the requester or a policy executor merely for creating it. A
// decision-time (reviewed) allow joins only as the executor's own: the
// capturing principal is that source's recorded audience, and other
// principals who happen to hold a fresh review are never enumerated
// (REQ-PER-008). A nil executor (a policy) admits no reviewed allow.
func defaultAudience(p Projection, executor *identity.Identity, now time.Time) ([]artifact.AudienceAssignment, time.Time, string) {
	var audience []artifact.AudienceAssignment
	var until time.Time
	for _, a := range p.Allows {
		if !identity.Fresh(a.ObservedAt, a.FreshUntil, now, 60*time.Second) || !permits(a.Audience.Role, ReadApproved) {
			continue
		}
		if a.Reviewed && (executor == nil || executor.Principal.Kind != identity.Human || !matches(a.Audience, *executor)) {
			continue
		}
		denied := false
		for _, d := range p.Denies {
			// Exact subject/group denies remove that positive audience. Overlapping
			// memberships are still checked for each reader on every later operation;
			// creating a capture does not enumerate an organization's group members.
			if d.Audience.Kind == a.Audience.Kind && d.Audience.Issuer == a.Audience.Issuer && d.Audience.SubjectID == a.Audience.SubjectID && permits(d.Audience.Role, ReadApproved) {
				denied = true
				break
			}
		}
		if denied {
			continue
		}
		audience = append(audience, a.Audience)
		if until.IsZero() {
			until = a.FreshUntil
		}
		until = identity.Earlier(until, a.FreshUntil)
	}
	if len(audience) == 0 {
		return nil, time.Time{}, "NoEvidenceAudience"
	}
	if len(audience) > 32 {
		return nil, time.Time{}, "AudienceOverflow"
	}
	sortAssignments(audience)
	return audience, until, ""
}

func sortAssignments(audience []artifact.AudienceAssignment) {
	slices.SortFunc(audience, func(a, b artifact.AudienceAssignment) int {
		if a.AssignmentID < b.AssignmentID {
			return -1
		}
		if a.AssignmentID > b.AssignmentID {
			return 1
		}
		return 0
	})
}
