package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
)

func TestInitialRetentionReviewBindsValuesSourceAndGuard(t *testing.T) {
	s := retentionJournalFixture().Snapshot
	now := s.ObservedAt
	guard := artifact.Digest{8}
	r := value.RetentionBootstrapReview{Resource: value.Resource{ClusterID: s.SourceClusterID, Namespace: "asservat-system", NamespaceUID: s.ControlNamespaceUID, Name: "retention-bootstrap", Kind: "ConfigMap", UID: "review", ResourceVersion: "review:1", SpecDigest: artifact.Digest{9}}, Reviewer: "installation-admin", PoliciesDigest: RetentionSnapshotDigest(s), ProtectionDigest: guard, ReviewedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	if err := CheckInitialRetention(s, guard, &r, now); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"nil", "values", "replacement", "cluster", "namespace", "guard", "expired", "future", "stale", "overlong", "deleting", "reviewer"} {
		t.Run(mode, func(t *testing.T) {
			changed, review, protection := s, r, guard
			var p = &review
			switch mode {
			case "nil":
				p = nil
			case "values":
				changed.Policies = append(changed.Policies[:0:0], s.Policies...)
				changed.Policies[0].Policy.MaximumSeconds++
			case "replacement":
				review.Resource.UID = ""
			case "cluster":
				review.Resource.ClusterID = "22222222-2222-4222-8222-222222222222"
			case "namespace":
				review.Resource.NamespaceUID = "replacement"
			case "guard":
				protection = artifact.Digest{7}
			case "expired":
				review.ExpiresAt = now
			case "future":
				review.ReviewedAt = now.Add(time.Second)
			case "stale":
				review.ObservedAt = now.Add(-10 * time.Second)
				review.FreshUntil = now.Add(-5 * time.Second)
			case "overlong":
				review.ExpiresAt = now.Add(2 * time.Hour)
			case "deleting":
				review.Resource.Deleting = true
			case "reviewer":
				review.Reviewer = ""
			}
			if CheckInitialRetention(changed, protection, p, now) == nil {
				t.Fatal("unreviewed source accepted")
			}
		})
	}
	s.Policies = nil
	s.Hub = false
	s.Revision.Digest = RetentionSnapshotDigest(s)
	if err := CheckInitialRetention(s, guard, nil, now); err != nil {
		t.Fatal("empty guarded source requires unnecessary review", err)
	}
	if CheckInitialRetention(s, artifact.Digest{}, nil, now) == nil {
		t.Fatal("empty source bypassed guard")
	}
	if CheckInitialRetention(s, guard, nil, now.Add(6*time.Second)) == nil {
		t.Fatal("empty source bypassed freshness")
	}
}
