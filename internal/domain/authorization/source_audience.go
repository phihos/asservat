package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"time"
)

// PolicyDefaultAudience is the same complete default reader set used for
// policy captures. It grants no collection authority; callers separately check
// the accepted policy and current complete permission projection.
func PolicyDefaultAudience(p Projection, now time.Time) ([]artifact.AudienceAssignment, time.Time, string) {
	return defaultAudience(p, nil, now)
}
