package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// The first LIST is accepted as listed (Helm renders the baseline policy
// under the platform's RBAC); it must still be the complete, fresh, guarded
// source snapshot.
func TestInitialRetentionAcceptsTheGuardedFreshList(t *testing.T) {
	s := retentionJournalFixture().Snapshot
	now := s.ObservedAt
	guard := artifact.Digest{8}
	if err := CheckInitialRetention(s, guard, now); err != nil {
		t.Fatal("listed baseline policy rejected", err)
	}
	changed := s
	changed.Policies = append(changed.Policies[:0:0], s.Policies...)
	changed.Policies[0].Policy.MaximumSeconds++
	if CheckInitialRetention(changed, guard, now) == nil {
		t.Fatal("snapshot whose revision digest no longer matches its values accepted")
	}
	s.Policies = nil
	s.Hub = false
	s.Revision.Digest = RetentionSnapshotDigest(s)
	if err := CheckInitialRetention(s, guard, now); err != nil {
		t.Fatal("empty guarded source rejected", err)
	}
	if CheckInitialRetention(s, artifact.Digest{}, now) == nil {
		t.Fatal("empty source bypassed guard")
	}
	if CheckInitialRetention(s, guard, now.Add(6*time.Second)) == nil {
		t.Fatal("empty source bypassed freshness")
	}
}
