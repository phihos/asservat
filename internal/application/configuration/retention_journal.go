package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"maps"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

// PolicyList preserves per-object versions separately from the semantic hash.
// Readiness additionally requires the persisted watch to reach the LIST's
// watermark: object equality cannot detect an unseen ADDED -> DELETED pair.
type PolicyList struct {
	Snapshot        value.PolicySnapshot
	ResourceVersion string
	Versions        map[string]string
	// Deleting is checkpoint state, not a current LIST assertion. Preserve it
	// across restarts so a resumed stream cannot clear a deletion in progress.
	Deleting map[string]bool
}
type PolicyEvent struct {
	Type, ResourceVersion string
	Policy                *value.ScopedPolicy
	Deleting              bool
}
type RetentionWatch interface {
	Next(context.Context) (PolicyEvent, error)
	Close()
}
type RetentionWatcher interface {
	WatchRetentionPolicies(context.Context, string) (RetentionWatch, error)
}
type RetentionListReader interface {
	RetentionPolicyList(context.Context) (PolicyList, error)
}

func RetentionSnapshotDigest(s value.PolicySnapshot) artifact.Digest {
	policies := append([]value.ScopedPolicy{}, s.Policies...)
	slices.SortFunc(policies, func(a, b value.ScopedPolicy) int {
		return comparePolicyUID(a.Policy.Revision.UID, b.Policy.Revision.UID)
	})
	b, _ := json.Marshal(struct {
		Cluster, Namespace string
		Hub                bool
		Policies           []value.ScopedPolicy
	}{s.SourceClusterID, s.ControlNamespaceUID, s.Hub, policies})
	v := jsontext.Value(b)
	if v.Canonicalize() != nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(v)
}
func comparePolicyUID(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
func clonePolicy(p value.ScopedPolicy) value.ScopedPolicy {
	p.Scope.ClusterIDs = slices.Clone(p.Scope.ClusterIDs)
	p.Scope.NamespaceLabels = maps.Clone(p.Scope.NamespaceLabels)
	p.Scope.WorkloadLabels = maps.Clone(p.Scope.WorkloadLabels)
	p.Policy.Rules = slices.Clone(p.Policy.Rules)
	for i := range p.Policy.Rules {
		p.Policy.Rules[i].PrivacyClasses = slices.Clone(p.Policy.Rules[i].PrivacyClasses)
		p.Policy.Rules[i].EvidenceTypes = slices.Clone(p.Policy.Rules[i].EvidenceTypes)
	}
	return p
}
func clonePolicyList(s PolicyList) PolicyList {
	s.Versions = maps.Clone(s.Versions)
	s.Deleting = maps.Clone(s.Deleting)
	s.Snapshot.Policies = slices.Clone(s.Snapshot.Policies)
	for i := range s.Snapshot.Policies {
		s.Snapshot.Policies[i] = clonePolicy(s.Snapshot.Policies[i])
	}
	return s
}
func validPolicyList(s PolicyList, now time.Time) bool {
	if !s.Snapshot.Valid(now) || !identity.Text(s.ResourceVersion, 128) || s.ResourceVersion == "0" || len(s.Versions) != len(s.Snapshot.Policies) || s.Snapshot.Revision.UID != s.Snapshot.ControlNamespaceUID || s.Snapshot.Revision.Generation != 1 || artifact.Digest(s.Snapshot.Revision.Digest) != RetentionSnapshotDigest(s.Snapshot) {
		return false
	}
	for _, p := range s.Snapshot.Policies {
		if !identity.Text(s.Versions[p.Policy.Revision.UID], 128) {
			return false
		}
	}
	for uid, deleting := range s.Deleting {
		if !deleting || s.Versions[uid] == "" {
			return false
		}
	}
	return true
}

// RetentionJournal has one serial owner. Checkpoint is never authority: the
// coordinator must durably accept each transition before calling Accepted.
// In particular, a later relaxed snapshot cannot replace a queued shortening.
type RetentionJournal struct {
	current            PolicyList
	accepted, poisoned bool
	pending            *PolicyList
	deleting           map[string]bool
}

func NewRetentionJournal(s PolicyList, now time.Time) (*RetentionJournal, error) {
	if !validPolicyList(s, now) {
		return nil, value.ErrInvalid
	}
	deleting := maps.Clone(s.Deleting)
	if deleting == nil {
		deleting = map[string]bool{}
	}
	return &RetentionJournal{current: clonePolicyList(s), deleting: deleting}, nil
}

// ResumeRetentionJournal resumes only an independently verified durable
// checkpoint. It does not renew observations or grant read/collection authority.
func ResumeRetentionJournal(s PolicyList) (*RetentionJournal, error) {
	j, err := NewRetentionJournal(s, s.Snapshot.ObservedAt)
	if err != nil {
		return nil, err
	}
	j.accepted = true
	return j, nil
}

// HistoricalCheckpoint preserves ordered obligations while replaying history
// after downtime. Only a fresh complete LIST and guard can make a source Ready.
func (j *RetentionJournal) HistoricalCheckpoint() (PolicyList, error) {
	return j.Checkpoint(j.current.Snapshot.ObservedAt)
}
func (j *RetentionJournal) Cursor() string { return j.current.ResourceVersion }
func (j *RetentionJournal) Checkpoint(now time.Time) (PolicyList, error) {
	if j.poisoned {
		return PolicyList{}, value.ErrUnavailable
	}
	if j.pending != nil {
		return clonePolicyList(*j.pending), nil
	} // original pending input, no fresh lease
	if !validPolicyList(j.current, now) {
		return PolicyList{}, value.ErrUnavailable
	}
	p := clonePolicyList(j.current)
	j.pending = &p
	return clonePolicyList(p), nil
}
func (j *RetentionJournal) Accepted(s PolicyList) error {
	if j.poisoned || j.pending == nil || !samePolicyList(*j.pending, s) {
		return value.ErrUnavailable
	}
	j.pending = nil
	j.accepted = true
	return nil
}
func samePolicyList(a, b PolicyList) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func (j *RetentionJournal) Apply(e PolicyEvent) error {
	if j.poisoned || !j.accepted || j.pending != nil {
		return value.ErrUnavailable
	}
	fail := func() error { j.poisoned = true; return value.ErrUnavailable }
	if !identity.Text(e.ResourceVersion, 128) || e.ResourceVersion == "0" {
		return fail()
	}
	if e.Type == "BOOKMARK" {
		if e.Policy != nil || e.Deleting {
			return fail()
		}
		j.current.ResourceVersion = e.ResourceVersion
		return nil
	}
	if e.Policy == nil {
		return fail()
	}
	p := clonePolicy(*e.Policy)
	s := j.current.Snapshot
	check := s
	check.Policies = []value.ScopedPolicy{p}
	// Event validation is structural; it never renews complete-list freshness.
	if !check.Valid(s.ObservedAt) {
		return fail()
	}
	index := -1
	for i, old := range s.Policies {
		if old.Policy.Revision.UID == p.Policy.Revision.UID {
			index = i
		} else if old.Name == p.Name {
			return fail()
		}
	}
	uid := p.Policy.Revision.UID
	switch e.Type {
	case "ADDED":
		if index >= 0 || len(s.Policies) >= 1024 {
			return fail()
		}
		s.Policies = append(s.Policies, p)
	case "MODIFIED", "DELETED":
		if index < 0 {
			return fail()
		}
		old := s.Policies[index]
		a, b := old.Policy.Revision, p.Policy.Revision
		if old.Name != p.Name || b.Generation < a.Generation || b.Generation > a.Generation+1 || (b.Generation == a.Generation && b.Digest != a.Digest) || (j.deleting[uid] && !e.Deleting && e.Type != "DELETED") {
			return fail()
		}
		if b.Generation == a.Generation || e.Type == "DELETED" {
			x, _ := json.Marshal(old)
			y, _ := json.Marshal(p)
			if string(x) != string(y) {
				return fail()
			}
		}
		if j.current.Versions[uid] == e.ResourceVersion {
			x, _ := json.Marshal(old)
			y, _ := json.Marshal(p)
			if e.Type == "DELETED" || string(x) != string(y) || e.Deleting != j.deleting[uid] {
				return fail()
			}
			return nil
		}
		if e.Type == "DELETED" {
			s.Policies = slices.Delete(s.Policies, index, index+1)
			delete(j.current.Versions, uid)
			delete(j.deleting, uid)
		} else {
			s.Policies[index] = p
		}
	default:
		return fail()
	}
	if e.Type != "DELETED" {
		j.current.Versions[uid] = e.ResourceVersion
		if e.Deleting {
			j.deleting[uid] = true
		} else {
			delete(j.deleting, uid)
		}
	}
	j.current.Deleting = maps.Clone(j.deleting)
	if len(j.current.Deleting) == 0 {
		j.current.Deleting = nil
	}
	slices.SortFunc(s.Policies, func(a, b value.ScopedPolicy) int {
		return comparePolicyUID(a.Policy.Revision.UID, b.Policy.Revision.UID)
	})
	s.Revision.Digest = RetentionSnapshotDigest(s)
	j.current.Snapshot = s
	j.current.ResourceVersion = e.ResourceVersion
	j.accepted = false
	return nil
}

// Confirm checks per-object agreement with processed history. Its caller must
// separately prove the watch cursor reached the LIST watermark; equality alone
// cannot rule out an entirely transient policy.
func (j *RetentionJournal) Confirm(s PolicyList, now time.Time) error {
	if j.poisoned || !j.accepted || j.pending != nil || !validPolicyList(s, now) || len(s.Deleting) != 0 || len(j.deleting) != 0 || s.Snapshot.SourceClusterID != j.current.Snapshot.SourceClusterID || s.Snapshot.ControlNamespaceUID != j.current.Snapshot.ControlNamespaceUID || s.Snapshot.Hub != j.current.Snapshot.Hub || s.Snapshot.Revision != j.current.Snapshot.Revision || !maps.Equal(s.Versions, j.current.Versions) || !s.Snapshot.ObservedAt.After(j.current.Snapshot.ObservedAt) {
		return value.ErrUnavailable
	}
	// Even status-only changes are processed before renewing completeness.
	j.current.Snapshot.ObservedAt = s.Snapshot.ObservedAt
	j.current.Snapshot.FreshUntil = s.Snapshot.FreshUntil
	return nil
}
func (j *RetentionJournal) Constrain(until time.Time) error {
	if j.poisoned || j.pending != nil || !until.After(j.current.Snapshot.ObservedAt) {
		return value.ErrUnavailable
	}
	j.current.Snapshot.FreshUntil = identity.Earlier(j.current.Snapshot.FreshUntil, until)
	return nil
}
