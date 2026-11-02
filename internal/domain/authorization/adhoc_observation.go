package authorization

import (
	"encoding/json"
	"time"
)

// AdHocObservationLimits reads the reviewed observation limits frozen in an
// approved ad hoc grant's plan scope (ADR-279); false without valid limits.
func AdHocObservationLimits(g Grant) (ObservationLimits, bool) {
	var scope struct {
		Approval *struct {
			ObservationLimits *struct {
				MaxSessionSeconds     int64 `json:"maxSessionSeconds"`
				MaxObservedBytes      int64 `json:"maxObservedBytes"`
				MaxBytesPerSecond     int64 `json:"maxBytesPerSecond"`
				MaxConcurrentSessions int64 `json:"maxConcurrentSessions"`
			} `json:"observationLimits"`
		} `json:"approval"`
	}
	if g.Kind != GrantAdHocCapture || json.Unmarshal(g.Scope, &scope) != nil || scope.Approval == nil || scope.Approval.ObservationLimits == nil {
		return ObservationLimits{}, false
	}
	l := scope.Approval.ObservationLimits
	out := ObservationLimits{MaxSessionSeconds: l.MaxSessionSeconds, MaxObservedBytes: l.MaxObservedBytes, MaxBytesPerSecond: l.MaxBytesPerSecond, MaxConcurrentSessions: l.MaxConcurrentSessions}
	return out, out.Valid()
}

// PlanFiniteAdHocObservation plans one finite manual raw session under an
// approved, current ad hoc grant with the same bounds as ADR-261: an active
// lease of at most 20 seconds within the reviewed session length, grant
// expiry and hard bounds; a latest start that still fits the recording; and a
// prepaid credit of the reviewed rate for the rounded duration plus one burst
// second, within the reviewed pool. The SQL debit enforces what remains.
func PlanFiniteAdHocObservation(g Grant, duration time.Duration, activeSessions int64, originalStartBy, hardUntil, now time.Time) (FinitePolicyObservation, error) {
	var zero FinitePolicyObservation
	limits, ok := AdHocObservationLimits(g)
	if !ok || g.Decision == nil || !g.Decision.Approved || !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
		return zero, ErrGrantScope
	}
	if duration < time.Second || duration > 15*time.Second || originalStartBy.IsZero() || hardUntil.IsZero() || !originalStartBy.After(now) || !hardUntil.After(now) || activeSessions < 0 || activeSessions >= limits.MaxConcurrentSessions {
		return zero, ErrGrantScope
	}
	until := now.Add(20 * time.Second)
	for _, bound := range []time.Time{now.Add(time.Duration(limits.MaxSessionSeconds) * time.Second), g.ExpiresAt, hardUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	latest := until.Add(-duration)
	if originalStartBy.Before(latest) {
		latest = originalStartBy
	}
	if !latest.After(now) {
		return zero, ErrGrantScope
	}
	seconds := int64((duration + time.Second - 1) / time.Second)
	credit := min(limits.MaxBytesPerSecond*(seconds+1), limits.MaxObservedBytes)
	return FinitePolicyObservation{StartedAt: now, Until: until, LatestStart: latest, Duration: duration, Credit: credit, BytesPerSecond: limits.MaxBytesPerSecond}, nil
}
