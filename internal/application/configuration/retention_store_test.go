package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

func retentionTransitionFixture(t *testing.T) (RetentionTransition, RetentionCheckpoint) {
	t.Helper()
	l := retentionJournalFixture()
	now := l.Snapshot.ObservedAt
	guard := artifact.Digest{4}
	id := "33333333-3333-4333-8333-333333333333"
	r := value.RetentionBootstrapReview{Resource: value.Resource{Kind: "ConfigMap", Name: "review", UID: "review", Namespace: "control", NamespaceUID: l.Snapshot.ControlNamespaceUID, ClusterID: l.Snapshot.SourceClusterID, ResourceVersion: "review:1", SpecDigest: artifact.Digest{6}}, Reviewer: "installer", PoliciesDigest: RetentionSnapshotDigest(l.Snapshot), ProtectionDigest: guard, ReviewedAt: now, ExpiresAt: now.Add(time.Hour), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	f := RetentionFence{RootID: id, Epoch: id, Source: privacy.PolicySourceRef{ClusterID: l.Snapshot.SourceClusterID, ControlNamespaceUID: l.Snapshot.ControlNamespaceUID, Hub: true, ProtectionDigest: guard}, LeaseUntil: now.Add(30 * time.Second)}
	x := RetentionTransition{ID: id, Fence: f, List: l, Review: &r}
	record, err := ValidateRetentionTransition(x, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return x, RetentionCheckpoint{Transition: x, Record: record}
}
func TestRetentionTransitionRequiresExactHistoryAndPreservesExpiredObligations(t *testing.T) {
	x, previous := retentionTransitionFixture(t)
	later := x.List.Snapshot.ObservedAt.Add(time.Minute)
	j, err := ResumeRetentionJournal(previous.Transition.List)
	if err != nil {
		t.Fatal(err)
	}
	lower := clonePolicy(x.List.Snapshot.Policies[0])
	lower.Policy.Revision.Generation++
	lower.Policy.Revision.Digest = artifact.Digest{8}
	lower.Policy.MaximumSeconds = 600
	e := PolicyEvent{Type: "MODIFIED", ResourceVersion: "opaque:lower", Policy: &lower}
	if err = j.Apply(e); err != nil {
		t.Fatal(err)
	}
	if _, err = j.Checkpoint(later); err == nil {
		t.Fatal("expired observation became current")
	}
	l, err := j.HistoricalCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	x.Fence.Sequence = 1
	x.Fence.LeaseUntil = later.Add(30 * time.Second)
	x.Fence.Epoch = "44444444-4444-4444-8444-444444444444"
	x.ID = x.Fence.Epoch
	x.Review = nil
	x.Event = &e
	x.List = l
	r, err := ValidateRetentionTransition(x, &previous, later)
	if err != nil || r.PreviousDigest != previous.Record.CheckpointDigest {
		t.Fatal("historical shortening lost", err)
	}
	for _, mode := range []string{"skip", "relist", "review", "source", "sequence", "missing-event", "lease"} {
		t.Run(mode, func(t *testing.T) {
			bad := x
			bad.List = clonePolicyList(x.List)
			switch mode {
			case "skip":
				policy := lower
				policy.Policy.Revision.Generation++
				event := e
				event.Policy = &policy
				bad.Event = &event
			case "relist":
				bad.List.Snapshot.ObservedAt = later
				bad.List.Snapshot.FreshUntil = later.Add(5 * time.Second)
			case "review":
				bad.Review = previous.Transition.Review
			case "source":
				bad.Fence.Source.Hub = false
			case "sequence":
				bad.Fence.Sequence++
			case "missing-event":
				bad.Event = nil
			case "lease":
				bad.Fence.LeaseUntil = later
			}
			if _, err := ValidateRetentionTransition(bad, &previous, later); err == nil {
				t.Fatal("invalid transition accepted")
			}
		})
	}
}
func TestRetentionCheckpointPreservesDeletionAcrossRestart(t *testing.T) {
	x, _ := retentionTransitionFixture(t)
	j, err := ResumeRetentionJournal(x.List)
	if err != nil {
		t.Fatal(err)
	}
	p := clonePolicy(x.List.Snapshot.Policies[0])
	e := PolicyEvent{Type: "MODIFIED", ResourceVersion: "deleting:2", Policy: &p, Deleting: true}
	if err = j.Apply(e); err != nil {
		t.Fatal(err)
	}
	l, err := j.HistoricalCheckpoint()
	if err != nil || !l.Deleting[p.Policy.Revision.UID] {
		t.Fatal("deletion checkpoint lost", err)
	}
	restored, err := ResumeRetentionJournal(l)
	if err != nil {
		t.Fatal(err)
	}
	e.Deleting = false
	e.ResourceVersion = "deleting:3"
	if restored.Apply(e) == nil {
		t.Fatal("restart cleared deletion")
	}
	// A checkpoint returned to a caller cannot mutate the journal's state.
	delete(l.Deleting, p.Policy.Revision.UID)
	original, err := j.HistoricalCheckpoint()
	if err != nil || !original.Deleting[p.Policy.Revision.UID] {
		t.Fatal("checkpoint shares caller maps")
	}
}
