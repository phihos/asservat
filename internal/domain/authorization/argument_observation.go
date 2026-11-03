package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"time"
)

// FiniteArgumentObservation is a bounded plan, never a permit. The caller must
// atomically debit both accepted policy and grant pools and persist one original
// source tuple before issuing its independently fenced observation permit.
type FiniteArgumentObservation struct {
	StartedAt, Until, LatestStart                            time.Time
	Duration                                                 time.Duration
	EventCredit, ByteCredit, EventsPerSecond, BytesPerSecond int64
}

func PlanFiniteAdHocArgumentObservation(g Grant, limits ObservationLimits, recording *artifact.Recording, activeSessions int64, originalStartBy, hardUntil, now time.Time) (FiniteArgumentObservation, error) {
	if g.Kind != GrantAdHocCapture || g.Decision == nil || !g.Decision.Approved || !g.RevokedAt.IsZero() || !now.Before(g.ExpiresAt) {
		return FiniteArgumentObservation{}, ErrGrantScope
	}
	return finiteArgumentObservation(limits, recording, limits.MaxObservedBytes, limits.MaxObservedEvents, activeSessions, originalStartBy, earlierArgumentTime(hardUntil, g.ExpiresAt), now)
}

func PlanFinitePolicyArgumentObservation(g Grant, a AcceptedPolicyAuthority, target Target, recording *artifact.Recording, remainingBytes, remainingEvents, activeSessions int64, originalStartBy, hardUntil, now time.Time) (FiniteArgumentObservation, error) {
	var zero FiniteArgumentObservation
	if !target.Valid() || CheckPolicyGrantCurrent(g, a, WorkloadTarget{target.ClusterID, target.NamespaceUID, target.WorkloadUID}, now) != nil || g.Policy.Observation == nil || remainingBytes < 1 || remainingBytes > a.Limits.MaxObservedBytes || remainingEvents < 1 || remainingEvents > a.Limits.MaxObservedEvents {
		return zero, ErrGrantScope
	}
	remainingBytes = min(remainingBytes, g.Policy.Limits.MaxObservedBytes-g.PolicySpend.ObservedBytes)
	remainingEvents = min(remainingEvents, g.Policy.Limits.MaxObservedEvents-g.PolicySpend.ObservedEvents)
	for _, end := range []time.Time{g.PolicyNotAfter, g.ExpiresAt, a.NotAfter} {
		hardUntil = earlierArgumentTime(hardUntil, end)
	}
	return finiteArgumentObservation(*g.Policy.Observation, recording, remainingBytes, remainingEvents, activeSessions, originalStartBy, hardUntil, now)
}

func earlierArgumentTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func finiteArgumentObservation(limits ObservationLimits, r *artifact.Recording, remainingBytes, remainingEvents, active int64, start, hard, now time.Time) (FiniteArgumentObservation, error) {
	var zero FiniteArgumentObservation
	if !limits.Valid() || limits.MaxObservedEvents < 1 || !r.Valid() || r.Kind != "syscallTrace" || r.Profile != "arguments" || !r.Arguments.Valid() || active < 0 || active >= limits.MaxConcurrentSessions || now.IsZero() || !start.After(now) || !hard.After(now) || r.Arguments.MaxBytesPerSecond > limits.MaxBytesPerSecond {
		return zero, ErrGrantScope
	}
	duration := time.Duration(r.DurationMillis) * time.Millisecond
	until := now.Add(duration + 10*time.Second)
	for _, end := range []time.Time{now.Add(time.Duration(limits.MaxSessionSeconds) * time.Second), hard} {
		until = earlierArgumentTime(until, end)
	}
	latest := earlierArgumentTime(start, until.Add(-duration))
	if !latest.After(now) || latest.After(now.Add(10*time.Second)) {
		return zero, ErrGrantScope
	}
	eventsRate, bytesRate := r.Syscalls.MaxEventsPerSecond, r.Arguments.MaxBytesPerSecond
	effective := min(eventsRate, bytesRate/r.Arguments.MaxProbeBytes)
	seconds := int64((duration+time.Second-1)/time.Second) + 1
	events := min(effective*seconds, limits.MaxObservedEvents, remainingEvents)
	bytes := min(bytesRate*seconds, limits.MaxObservedBytes, remainingBytes)
	if effective < 1 || events < 1 || bytes < r.Arguments.MaxProbeBytes {
		return zero, ErrPolicyGrantBudgetExhausted
	}
	return FiniteArgumentObservation{StartedAt: now, Until: until, LatestStart: latest, Duration: duration, EventCredit: events, ByteCredit: bytes, EventsPerSecond: eventsRate, BytesPerSecond: bytesRate}, nil
}
