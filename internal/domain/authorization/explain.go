package authorization

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

var ErrExplainInvalid = errors.New("invalid access explanation request")

// Decision is the explained outcome of the ordinary evaluator (ADR-234).
type Decision string

const (
	Allow         Decision = "Allow"
	Deny          Decision = "Deny"
	Indeterminate Decision = "Indeterminate"
)

// Unmet names the evaluator condition that decided a refusal.
const (
	UnmetNoMatchingAllow    = "NoMatchingAllow"
	UnmetExplicitDeny       = "ExplicitDeny"
	UnmetClientScope        = "ClientScopeMissing"
	UnmetPermissionStale    = "PermissionObservationStale"
	UnmetIdentity           = "IdentityUnavailable"
	UnmetAudienceOverflow   = "AudienceOverflow"
	UnmetServiceUnavailable = "ServiceUnavailable"
)

// ExplainedAssignment is one of the caller's own assignments that decided the
// result: an allow that contributed, or the deny that names the caller.
type ExplainedAssignment struct {
	Effect     string // "allow" or "deny"
	Assignment artifact.AudienceAssignment
}

// Explanation describes the caller's own ordinary decision for one exact
// whole-pod target and operation. It is a query result, never a permit.
// Disclosed is false for the uniform answer that a caller without any
// assignment on the target receives, so the reply cannot reveal whether the
// workload exists or which other bindings apply to it.
type Explanation struct {
	Decision     Decision
	Unmet        string
	MissingScope string
	Disclosed    bool
	Target       Target
	Assignments  []ExplainedAssignment
	ValidUntil   time.Time
}

// RequiredRoles lists the roles whose allow assignment permits op, from the
// evaluator's own role table.
func RequiredRoles(op Operation) []string {
	var out []string
	for _, role := range []string{"evidence-reader", "workload-maintainer", "evidence-owner", "action-approver"} {
		if permits(role, op) {
			out = append(out, role)
		}
	}
	return out
}

// Undisclosed is the uniform explanation for a caller who has no assignment on
// the target, or a target that does not resolve: no matching allow.
func Undisclosed() Explanation {
	return Explanation{Decision: Deny, Unmet: UnmetNoMatchingAllow}
}

// Explain runs the ordinary target evaluator (ScopeEligibility) for the
// caller and reports which of its conditions decided the result. It does not
// evaluate retained artifact audiences, shares or other principals. Details
// are disclosed only when the projection lists at least one assignment that
// matches the caller (any role, fresh or not): such a caller already learned
// of the target through that binding. Freshness of that listing is used only
// to decide what to reveal, never to authorize.
func Explain(i identity.Identity, p Projection, op Operation, t Target, now time.Time) Explanation {
	r, d := evaluateDetail(i, p, op, t, nil, now, false)
	visible := p.Target == t && slices.ContainsFunc(p.Allows, func(a CurrentAssignment) bool { return matches(a.Audience, i) })
	if !visible {
		if r.Reason == "IdentityUnavailable" {
			return Explanation{Decision: Indeterminate, Unmet: UnmetIdentity}
		}
		return Undisclosed()
	}
	out := Explanation{Disclosed: true, Target: t}
	switch r.Reason {
	case "Eligible":
		out.Decision, out.ValidUntil = Allow, r.ValidUntil
		for _, a := range r.ContributingAssignments {
			out.Assignments = append(out.Assignments, ExplainedAssignment{"allow", a})
		}
	case "ExplicitDeny":
		out.Decision, out.Unmet = Deny, UnmetExplicitDeny
		if d.matchedDeny != nil {
			out.Assignments = []ExplainedAssignment{{"deny", *d.matchedDeny}}
		}
	case "InsufficientScope":
		out.Decision, out.Unmet, out.MissingScope = Deny, UnmetClientScope, d.missingScope
	case "NoEntitlement":
		out.Decision, out.Unmet = Deny, UnmetNoMatchingAllow
		if d.staleAllow {
			out.Decision, out.Unmet = Indeterminate, UnmetPermissionStale
		}
	case "AudienceOverflow":
		out.Decision, out.Unmet = Deny, UnmetAudienceOverflow
	case "PermissionUnavailable":
		out.Decision, out.Unmet = Indeterminate, UnmetPermissionStale
	case "IdentityUnavailable":
		out.Decision, out.Unmet = Indeterminate, UnmetIdentity
	default:
		out.Decision, out.Unmet = Indeterminate, UnmetServiceUnavailable
	}
	return out
}
