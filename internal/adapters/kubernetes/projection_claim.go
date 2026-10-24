package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// minimumProjectionClaim is the least validity a new projection claim may
// start with. A claim is irreplaceable once attempted (an unknown CAS never
// owns CREATE), so one written with milliseconds left could never complete
// (installed native 58: 3 ms). Declining earlier starts no effect; the caller
// retries with a fresh bracket. This mirrors the one-second worker admission
// floor and never extends any original deadline.
const minimumProjectionClaim = time.Second

// projectionClaimUntil returns the claim's original end, the earlier of the
// call deadline and the retained state's end, if at least
// minimumProjectionClaim of it remains.
func projectionClaimUntil(now, deadline, stateUntil time.Time) (time.Time, bool) {
	until := identity.Earlier(deadline, stateUntil).UTC().Truncate(time.Microsecond)
	return until, now.Add(minimumProjectionClaim).Before(until)
}
