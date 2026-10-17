package privacy

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Snapshot and scoped policies are observations, not proof of write protection.
// Hub origin is fixed by enrollment/bootstrap wiring; no CRD field can set it.
type PolicyScope struct {
	ClusterIDs                      []string
	NamespaceLabels, WorkloadLabels map[string]string
}
type ScopedPolicy struct {
	Name                                     string
	Policy                                   Policy
	Scope                                    PolicyScope
	CaseDefaultSeconds, CaseMaximumSeconds   int64
	AuditDefaultSeconds, AuditMaximumSeconds int64
	LegalExceptions                          string
}
type PolicySnapshot struct {
	SourceClusterID, ControlNamespaceUID string
	Hub                                  bool
	Revision                             identity.Revision
	ObservedAt, FreshUntil               time.Time
	Policies                             []ScopedPolicy
}

func (s PolicyScope) Empty() bool {
	return len(s.ClusterIDs) == 0 && len(s.NamespaceLabels) == 0 && len(s.WorkloadLabels) == 0
}
func (s PolicyScope) Valid() bool {
	if !identity.Strings(s.ClusterIDs, 100, 36) || len(s.NamespaceLabels) > 16 || len(s.WorkloadLabels) > 16 {
		return false
	}
	for _, id := range s.ClusterIDs {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, labels := range []map[string]string{s.NamespaceLabels, s.WorkloadLabels} {
		for k, v := range labels {
			if !identity.Text(k, 253) || !identity.Text(v, 63) {
				return false
			}
		}
	}
	return true
}
func (s PolicySnapshot) Valid(now time.Time) bool {
	if !authorization.UUID(s.SourceClusterID) || !identity.Text(s.ControlNamespaceUID, 64) || !s.Revision.Valid() || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) || len(s.Policies) > 1024 {
		return false
	}
	seenUID, seenName := map[string]bool{}, map[string]bool{}
	for _, p := range s.Policies {
		if !identity.Text(p.Name, 253) || seenUID[p.Policy.Revision.UID] || seenName[p.Name] || !p.Policy.Valid() || !p.Scope.Valid() || p.Policy.Baseline != (s.Hub && p.Scope.Empty()) || !age(p.CaseDefaultSeconds) || !age(p.CaseMaximumSeconds) || !age(p.AuditDefaultSeconds) || !age(p.AuditMaximumSeconds) || (p.LegalExceptions != "disabled" && p.LegalExceptions != "reviewed") {
			return false
		}
		seenUID[p.Policy.Revision.UID], seenName[p.Name] = true, true
	}
	return true
}

// SelectorFacts must be produced by the source/metadata guard, not merely a
// successful API GET. Complete protected key sets include absent label values.
type SelectorFacts struct {
	Target                          authorization.Target
	Revision                        identity.Revision
	ObservedAt, FreshUntil          time.Time
	NamespaceLabels, WorkloadLabels map[string]string
	NamespaceKeys, WorkloadKeys     []string
}

func (f SelectorFacts) Valid(now time.Time) bool {
	if !f.Target.Valid() || !f.Revision.Valid() || !identity.Fresh(f.ObservedAt, f.FreshUntil, now, 5*time.Second) || !identity.Strings(f.NamespaceKeys, 64, 253) || !identity.Strings(f.WorkloadKeys, 64, 253) {
		return false
	}
	for i, labels := range []map[string]string{f.NamespaceLabels, f.WorkloadLabels} {
		keys := f.NamespaceKeys
		if i == 1 {
			keys = f.WorkloadKeys
		}
		for k, v := range labels {
			if !slices.Contains(keys, k) || len(v) > 63 {
				return false
			}
		}
	}
	return true
}

// MatchPolicies intersects only a complete configured hub/local source set.
// The caller must establish source protection and topology completeness first.
// Nonmatching cluster scope does not require unrelated selector observations.
func MatchPolicies(snapshots []PolicySnapshot, f SelectorFacts, now time.Time) ([]Policy, time.Time, error) {
	return matchPolicies(snapshots, f, nil, now)
}

// Retained matching also follows the policy UIDs recorded at acquisition even
// when protected selectors change. Deletion of an override cannot extend the
// existing ledger dates. Rollback/reuse of a recorded revision fails closed.
func MatchRetainedPolicies(snapshots []PolicySnapshot, f SelectorFacts, origins []artifact.RetentionRule, now time.Time) ([]Policy, time.Time, error) {
	if !ValidPolicyOrigins(origins) {
		return nil, time.Time{}, ErrInvalid
	}
	return matchPolicies(snapshots, f, origins, now)
}
func ValidPolicyOrigins(origins []artifact.RetentionRule) bool {
	if len(origins) < 1 || len(origins) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range origins {
		if !identity.Text(r.UID, 64) || seen[r.UID] || r.Generation < 1 || r.Generation > 2147483647 || r.Digest == (artifact.Digest{}) {
			return false
		}
		seen[r.UID] = true
	}
	return true
}
func matchPolicies(snapshots []PolicySnapshot, f SelectorFacts, origins []artifact.RetentionRule, now time.Time) ([]Policy, time.Time, error) {
	original := map[string]artifact.RetentionRule{}
	for _, r := range origins {
		original[r.UID] = r
	}
	if !f.Valid(now) || len(snapshots) < 1 || len(snapshots) > 2 {
		return nil, time.Time{}, ErrUnavailable
	}
	until := f.FreshUntil
	hubs, baselines := 0, 0
	seenSource, seenPolicy := map[string]bool{}, map[string]bool{}
	var out []Policy
	for _, s := range snapshots {
		source := s.SourceClusterID + "/" + s.ControlNamespaceUID
		if !s.Valid(now) || seenSource[source] || (!s.Hub && s.SourceClusterID != f.Target.ClusterID) {
			return nil, time.Time{}, ErrUnavailable
		}
		seenSource[source] = true
		if s.Hub {
			hubs++
		}
		until = identity.Earlier(until, s.FreshUntil)
		for _, p := range s.Policies {
			if p.Policy.Baseline {
				baselines++
			}
			origin, wasApplied := original[p.Policy.Revision.UID]
			if wasApplied && (p.Policy.Revision.Generation < origin.Generation || (p.Policy.Revision.Generation == origin.Generation && artifact.Digest(p.Policy.Revision.Digest) != origin.Digest)) {
				return nil, time.Time{}, ErrUnavailable
			}
			if !wasApplied && len(p.Scope.ClusterIDs) > 0 && !slices.Contains(p.Scope.ClusterIDs, f.Target.ClusterID) {
				continue
			}
			matches := true
			for i, selector := range []map[string]string{p.Scope.NamespaceLabels, p.Scope.WorkloadLabels} {
				keys, labels := f.NamespaceKeys, f.NamespaceLabels
				if i == 1 {
					keys, labels = f.WorkloadKeys, f.WorkloadLabels
				}
				for k, v := range selector {
					if wasApplied {
						continue
					} // historical applicability needs no current label proof
					if !slices.Contains(keys, k) {
						return nil, time.Time{}, ErrUnavailable
					}
					if labels[k] != v {
						matches = false
					}
				}
			}
			if !matches && !wasApplied {
				continue
			}
			if seenPolicy[p.Policy.Revision.UID] {
				return nil, time.Time{}, ErrUnavailable
			}
			seenPolicy[p.Policy.Revision.UID] = true
			policy := p.Policy
			policy.Rules = slices.Clone(policy.Rules)
			for i := range policy.Rules {
				policy.Rules[i].PrivacyClasses = slices.Clone(policy.Rules[i].PrivacyClasses)
				policy.Rules[i].EvidenceTypes = slices.Clone(policy.Rules[i].EvidenceTypes)
			}
			out = append(out, policy)
			if len(out) > 64 {
				return nil, time.Time{}, ErrUnavailable
			}
		}
	}
	if hubs != 1 || baselines != 1 {
		return nil, time.Time{}, ErrUnavailable
	}
	slices.SortFunc(out, func(a, b Policy) int {
		if a.Revision.UID < b.Revision.UID {
			return -1
		}
		if a.Revision.UID > b.Revision.UID {
			return 1
		}
		return 0
	})
	return out, until, nil
}
