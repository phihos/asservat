package authorization

import (
	"errors"
	"slices"
	"time"
)

var ErrPolicyGrantBudgetExhausted = errors.New("policy grant budget exhausted")

// PolicyGrantSpend is separate from the human result-disclosure counters.
// Values count conservative reservations, including unknown effects; reporting
// fewer retained bytes or replacing an attachment cannot refund these pools.
type PolicyGrantSpend struct{ Executions, CollectedBytes, ObservedBytes int64 }

func (s PolicyGrantSpend) valid(p *PolicyGrantScope) bool {
	return p != nil && s.Executions >= 0 && s.Executions <= p.Limits.MaxExecutions && s.CollectedBytes >= 0 && s.CollectedBytes <= p.Limits.MaxBytes && s.ObservedBytes >= 0 && s.ObservedBytes <= p.Limits.MaxObservedBytes
}
func (s PolicyGrantSpend) Exhausted(p *PolicyGrantScope) bool {
	return p != nil && (s.Executions >= p.Limits.MaxExecutions || s.CollectedBytes >= p.Limits.MaxBytes || p.Observation != nil && s.ObservedBytes >= p.Limits.MaxObservedBytes)
}

// CheckPolicyGrantCurrent is team-authority preflight, not an effect permit.
// Current delegation, complete denies, recovery, accepted source and atomic
// quota checks are still required by the consumer. No requester login/group
// snapshot is used: requester is historical review/audit provenance only.
// Exhausted pools do not invalidate already-prepaid observation credit.
func CheckPolicyGrantCurrent(g Grant, a AcceptedPolicyAuthority, target WorkloadTarget, now time.Time) error {
	if !g.Valid() {
		return ErrGrantInvalid
	}
	if g.Kind != GrantPolicy || g.Policy == nil {
		return ErrGrantScope
	}
	phase := g.Phase(now)
	if phase != GrantApproved && phase != GrantExhausted {
		return phaseError(phase)
	}
	if !target.Valid() || g.Policy.Workload() != target || !a.Valid(now) {
		return ErrGrantScope
	}
	old := g.Policy.Authority
	if a.InstallationID != old.InstallationID || a.PolicyUID != old.PolicyUID || a.Creator != old.Creator || a.Executor != old.Executor || a.ScopeDigest != old.ScopeDigest || a.ClusterID != old.ClusterID || a.NamespaceUID != old.NamespaceUID || a.WorkloadUID != old.WorkloadUID || a.Delegation != old.Delegation || a.Limits != old.Limits || !a.IssuedAt.Equal(old.IssuedAt) || !a.NotAfter.Equal(old.NotAfter) || !slices.Equal(a.Owners, old.Owners) || !slices.Equal(a.Actions, old.Actions) {
		return ErrGrantScope
	}
	return nil
}

// CheckPolicyCapture requires a real resolved Pod of the approved workload and
// one finite prospective output reservation. SQL consumes this and the policy's
// own shared budget atomically with capture admission and its idempotent use ID.
func CheckPolicyCapture(g Grant, a AcceptedPolicyAuthority, target Target, maxOutputBytes int64, now time.Time) error {
	if !target.Valid() {
		return ErrGrantScope
	}
	if err := CheckPolicyGrantCurrent(g, a, WorkloadTarget{target.ClusterID, target.NamespaceUID, target.WorkloadUID}, now); err != nil {
		return err
	}
	if maxOutputBytes < 1 || g.PolicySpend.Executions >= g.Policy.Limits.MaxExecutions || maxOutputBytes > g.Policy.Limits.MaxBytes-g.PolicySpend.CollectedBytes {
		return ErrPolicyGrantBudgetExhausted
	}
	return nil
}

// CheckPolicyObservationStart checks one initial finite session reservation.
// Concurrent counts come from still-live original session/fence rows under the
// same SQL lock; ending a viewer or reporting no retained output releases none
// of the prepaid bytes. The first finite mode has no renewal or credit growth.
func CheckPolicyObservationStart(g Grant, a AcceptedPolicyAuthority, target Target, duration time.Duration, credit, activeSessions int64, now time.Time) error {
	if !target.Valid() {
		return ErrGrantScope
	}
	if err := CheckPolicyGrantCurrent(g, a, WorkloadTarget{target.ClusterID, target.NamespaceUID, target.WorkloadUID}, now); err != nil {
		return err
	}
	p := g.Policy.Observation
	if p == nil || duration <= 0 || duration > time.Duration(p.MaxSessionSeconds)*time.Second {
		return ErrGrantScope
	}
	if credit < 1 || activeSessions < 0 || activeSessions >= p.MaxConcurrentSessions || credit > g.Policy.Limits.MaxObservedBytes-g.PolicySpend.ObservedBytes {
		return ErrPolicyGrantBudgetExhausted
	}
	return nil
}

// FinitePolicyObservation is the original one-shot admission, not authority by
// itself. SQL must atomically bind/charge it after current checks and locks.
// Credit is conservative reservation, never a measured byte count.
type FinitePolicyObservation struct {
	StartedAt, Until, LatestStart time.Time
	Duration                      time.Duration
	Credit, BytesPerSecond        int64
}

// PlanFinitePolicyObservation implements ADR-261's first policy-only window.
// originalStartBy comes from the existing private start allowance; hardUntil
// intersects capture/retention/local hard expiries, not transient check intervals.
// The consumer still checks current source/denies/recovery after blocking work.
func PlanFinitePolicyObservation(g Grant, a AcceptedPolicyAuthority, target Target, duration time.Duration, policyRemaining, activeSessions int64, originalStartBy, hardUntil, now time.Time) (FinitePolicyObservation, error) {
	var zero FinitePolicyObservation
	if duration < time.Second || duration > 15*time.Second || originalStartBy.IsZero() || hardUntil.IsZero() || !originalStartBy.After(now) || !hardUntil.After(now) || policyRemaining < 1 || policyRemaining > a.Limits.MaxObservedBytes {
		return zero, ErrGrantScope
	}
	if err := CheckPolicyGrantCurrent(g, a, WorkloadTarget{target.ClusterID, target.NamespaceUID, target.WorkloadUID}, now); err != nil {
		return zero, err
	}
	if g.Policy.Observation == nil {
		return zero, ErrGrantScope
	}
	limits := g.Policy.Observation
	until := now.Add(20 * time.Second)
	for _, bound := range []time.Time{now.Add(time.Duration(limits.MaxSessionSeconds) * time.Second), g.PolicyNotAfter, g.ExpiresAt, a.NotAfter, hardUntil} {
		if bound.Before(until) {
			until = bound
		}
	}
	latest := until.Add(-duration)
	if originalStartBy.Before(latest) {
		latest = originalStartBy
	}
	// Starting exactly at issuance is not a usable dispatch interval. Never
	// enlarge an original reviewed session merely to fit the requested duration.
	if !latest.After(now) {
		return zero, ErrGrantScope
	}
	seconds := int64((duration + time.Second - 1) / time.Second)
	credit := min(limits.MaxBytesPerSecond*(seconds+1), limits.MaxObservedBytes, g.Policy.Limits.MaxObservedBytes-g.PolicySpend.ObservedBytes, policyRemaining)
	if err := CheckPolicyObservationStart(g, a, target, until.Sub(now), credit, activeSessions, now); err != nil {
		return zero, err
	}
	return FinitePolicyObservation{StartedAt: now, Until: until, LatestStart: latest, Duration: duration, Credit: credit, BytesPerSecond: limits.MaxBytesPerSecond}, nil
}
