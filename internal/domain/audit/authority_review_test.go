package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestReviewDecisionChangeRecordIsBoundedAndClosed(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	id := "11111111-1111-4111-8111-111111111111"
	change := ReviewDecisionChange{Change: ReviewGranted, Outcome: "Allowed", SourceUID: "exec", SourceGeneration: 1, SourceDigest: artifact.Digest{1}, IdentityMapping: "company", Issuer: "https://id.example.invalid", Subject: "alice",
		AssignmentID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "w", PodUID: "p", DecidedAt: now, FreshUntil: now.Add(30 * time.Second)}
	record := func(c ReviewDecisionChange) AuthorityRecord {
		return AuthorityRecord{ID: id, RootID: id, Epoch: id, Sequence: 3, Kind: "permission-review", InputDigest: artifact.Digest{2}, CreatedAt: now, Review: &c}
	}
	if !record(change).Valid() {
		t.Fatal("granted change refused")
	}
	revoked := change
	revoked.Change, revoked.Outcome, revoked.FreshUntil = ReviewRevoked, "Denied", now
	if !record(revoked).Valid() {
		t.Fatal("revoked change refused")
	}
	for name, edit := range map[string]func(*ReviewDecisionChange){
		"unknown change":        func(c *ReviewDecisionChange) { c.Change = "renewed" },
		"granted denial":        func(c *ReviewDecisionChange) { c.Outcome = "Denied" },
		"over 60s":              func(c *ReviewDecisionChange) { c.FreshUntil = now.Add(61 * time.Second) },
		"revoked with lifetime": func(c *ReviewDecisionChange) { c.Change, c.Outcome = ReviewRevoked, "Denied" },
		"no assignment":         func(c *ReviewDecisionChange) { c.AssignmentID = "" },
	} {
		c := change
		edit(&c)
		if record(c).Valid() {
			t.Errorf("%s accepted", name)
		}
	}
	r := record(change)
	r.Kind = "permission-change"
	if r.Valid() {
		t.Fatal("review payload on another event kind")
	}
	r = record(change)
	r.Review = nil
	if r.Valid() {
		t.Fatal("review event without payload")
	}
}
