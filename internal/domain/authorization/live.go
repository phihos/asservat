package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

// LiveSourceEligibility requires current maintainer entitlement AND ordinary
// read rights still present in the original source audience. It accepts no
// artifact share or raw grant and needs only the read token scope; a live view
// cannot collect, download or inspect raw contents.
func LiveSourceEligibility(i identity.Identity, p Projection, target Target, audience []artifact.AudienceAssignment, sourceUntil time.Time, now time.Time) Result {
	maintain := ScopeEligibility(i, p, ReadLiveSource, target, now)
	if !maintain.Eligible {
		return maintain
	}
	if len(audience) == 0 || len(audience) > 256 || !now.Before(sourceUntil) {
		return Result{Reason: "SourceUnavailable"}
	}
	for _, a := range audience {
		if !validAudience(a) {
			return Result{Reason: "SourceUnavailable"}
		}
	}
	retained := p
	retained.Allows = make([]CurrentAssignment, 0, len(p.Allows))
	for _, a := range p.Allows {
		if slices.Contains(audience, a.Audience) {
			retained.Allows = append(retained.Allows, a)
		}
	}
	read := ScopeEligibility(i, retained, ReadApproved, target, now)
	if read.Eligible {
		read.ValidUntil = identity.Earlier(read.ValidUntil, identity.Earlier(maintain.ValidUntil, sourceUntil))
	}
	return read
}
