package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"testing"
	"time"
)

func retentionJournalFixture() PolicyList {
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := value.ScopedPolicy{Name: "baseline", Policy: value.Policy{Revision: identity.Revision{UID: "baseline-uid", Generation: 1, Digest: [32]byte{2}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 7200, DeletionBudgetSeconds: 300}, CaseDefaultSeconds: 3600, CaseMaximumSeconds: 7200, AuditDefaultSeconds: 3600, AuditMaximumSeconds: 7200, LegalExceptions: "disabled"}
	s := value.PolicySnapshot{SourceClusterID: "11111111-1111-4111-8111-111111111111", ControlNamespaceUID: "control", Hub: true, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Policies: []value.ScopedPolicy{p}}
	s.Revision = identity.Revision{UID: s.ControlNamespaceUID, Generation: 1, Digest: RetentionSnapshotDigest(s)}
	return PolicyList{Snapshot: s, ResourceVersion: "opaque:initial", Versions: map[string]string{p.Policy.Revision.UID: "opaque:1"}}
}
func checkpointRetention(t *testing.T, j *RetentionJournal, now time.Time) PolicyList {
	t.Helper()
	p, err := j.Checkpoint(now)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Accepted(p); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestRetentionJournalNeverCoalescesAnIntermediateShortening(t *testing.T) {
	s := retentionJournalFixture()
	now := s.Snapshot.ObservedAt
	j, err := NewRetentionJournal(s, now)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRetention(t, j, now)
	original := s.Snapshot.Policies[0]
	lower := clonePolicy(original)
	lower.Policy.MaximumSeconds = 600
	lower.Policy.Revision.Generation = 2
	lower.Policy.Revision.Digest = artifact.Digest{3}
	raised := clonePolicy(original)
	raised.Policy.Revision.Generation = 3
	// A final LIST cannot substitute for the intervening watch transitions.
	latest := clonePolicyList(s)
	latest.Snapshot.Policies[0] = raised
	latest.Snapshot.Revision.Digest = RetentionSnapshotDigest(latest.Snapshot)
	latest.Versions[original.Policy.Revision.UID] = "opaque:3"
	latest.Snapshot.ObservedAt = now.Add(time.Second)
	latest.Snapshot.FreshUntil = now.Add(6 * time.Second)
	if j.Confirm(latest, now.Add(time.Second)) == nil {
		t.Fatal("later list skipped lowering")
	}
	if err = j.Apply(PolicyEvent{Type: "MODIFIED", ResourceVersion: "opaque:2", Policy: &lower}); err != nil {
		t.Fatal(err)
	}
	if j.Apply(PolicyEvent{Type: "MODIFIED", ResourceVersion: "opaque:3", Policy: &raised}) == nil {
		t.Fatal("unaccepted transition discarded")
	}
	pending, err := j.Checkpoint(now)
	if err != nil || pending.Snapshot.Policies[0].Policy.MaximumSeconds != 600 {
		t.Fatal("lowering lost", err)
	}
	replay, err := j.Checkpoint(now.Add(time.Hour))
	if err != nil || !samePolicyList(pending, replay) {
		t.Fatal("pending retry renewed lifetime", err)
	}
	changed := clonePolicyList(pending)
	changed.Snapshot.FreshUntil = changed.Snapshot.FreshUntil.Add(time.Second)
	if j.Accepted(changed) == nil {
		t.Fatal("different checkpoint accepted")
	}
	if err = j.Accepted(pending); err != nil {
		t.Fatal(err)
	}
	if err = j.Apply(PolicyEvent{Type: "MODIFIED", ResourceVersion: "opaque:3", Policy: &raised}); err != nil {
		t.Fatal(err)
	}
	checkpointRetention(t, j, now)
	if err = j.Confirm(latest, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if j.Cursor() != "opaque:3" {
		t.Fatal("LIST replaced watch cursor")
	}
	if err = j.Apply(PolicyEvent{Type: "BOOKMARK", ResourceVersion: "opaque:bookmark"}); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Checkpoint(now.Add(7 * time.Second)); err == nil {
		t.Fatal("bookmark renewed completeness")
	}
}
func TestRetentionJournalPoisonsGapsAndKeepsCallerBuffersIndependent(t *testing.T) {
	for _, mode := range []string{"generation-gap", "changed-same-generation", "deleted-missing-update", "unknown-type", "replaced-name", "revived-deleting"} {
		t.Run(mode, func(t *testing.T) {
			s := retentionJournalFixture()
			now := s.Snapshot.ObservedAt
			j, err := NewRetentionJournal(s, now)
			if err != nil {
				t.Fatal(err)
			}
			checkpointRetention(t, j, now)
			p := clonePolicy(s.Snapshot.Policies[0])
			e := PolicyEvent{Type: "MODIFIED", ResourceVersion: "opaque:2", Policy: &p}
			switch mode {
			case "generation-gap":
				p.Policy.Revision.Generation = 3
			case "changed-same-generation":
				p.Policy.MaximumSeconds = 600
			case "deleted-missing-update":
				e.Type = "DELETED"
				p.Policy.Revision.Generation = 2
				p.Policy.Revision.Digest[0]++
				p.Policy.MaximumSeconds = 600
			case "unknown-type":
				e.Type = "ERROR"
			case "replaced-name":
				p.Name = "different"
			case "revived-deleting":
				e.Deleting = true
				if err = j.Apply(e); err != nil {
					t.Fatal(err)
				}
				checkpointRetention(t, j, now)
				e.Deleting = false
				e.ResourceVersion = "opaque:3"
			}
			if err = j.Apply(e); err == nil {
				t.Fatal("lost history accepted")
			}
			if _, err = j.Checkpoint(now); err == nil {
				t.Fatal("poisoned journal resumed")
			}
		})
	}
	s := retentionJournalFixture()
	now := s.Snapshot.ObservedAt
	j, err := NewRetentionJournal(s, now)
	if err != nil {
		t.Fatal(err)
	}
	s.Snapshot.Policies[0].Policy.MaximumSeconds = 900
	s.Versions["baseline-uid"] = "mutated"
	p, err := j.Checkpoint(now)
	if err != nil || p.Snapshot.Policies[0].Policy.MaximumSeconds != 7200 || p.Versions["baseline-uid"] != "opaque:1" {
		t.Fatal("caller changed journal", err)
	}
	p.Snapshot.Policies[0].Policy.MaximumSeconds = 1000
	if j.Accepted(p) == nil {
		t.Fatal("caller changed pending checkpoint")
	}
}
func TestRetentionJournalEmptySnapshotsHaveStableDigest(t *testing.T) {
	s := retentionJournalFixture()
	j, err := NewRetentionJournal(s, s.Snapshot.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	checkpointRetention(t, j, s.Snapshot.ObservedAt)
	p := s.Snapshot.Policies[0]
	if err = j.Apply(PolicyEvent{Type: "DELETED", ResourceVersion: "opaque:deleted", Policy: &p}); err != nil {
		t.Fatal(err)
	}
	pending := checkpointRetention(t, j, s.Snapshot.ObservedAt)
	s.Snapshot.Policies = nil
	s.Versions = map[string]string{}
	s.Snapshot.Revision.Digest = RetentionSnapshotDigest(s.Snapshot)
	s.Snapshot.ObservedAt = s.Snapshot.ObservedAt.Add(time.Second)
	s.Snapshot.FreshUntil = s.Snapshot.FreshUntil.Add(time.Second)
	if pending.Snapshot.Revision != s.Snapshot.Revision || j.Confirm(s, s.Snapshot.ObservedAt) != nil {
		t.Fatal("nil/empty changed policy identity")
	}
}
