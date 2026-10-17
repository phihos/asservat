package configuration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
)

func TestBindingAcceptancePreservesAutomationEnvelope(t *testing.T) {
	_, snapshot, fence, now := journalFixture(t)
	snapshot.Bindings[0].Automation = &authorization.AutomationEnvelope{AllowedActions: []string{"logs"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 1024}
	j, err := NewBindingJournal(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := j.Prepare(fence, journalID, now)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(b.Bases)
	if err != nil || !bytes.Contains(encoded, []byte(`"Automation"`)) || !bytes.Contains(encoded, []byte(`"logs"`)) {
		t.Fatal("accepted configuration discarded the bounded automation envelope", err)
	}
	b.Bases[0].Automation.AllowedActions[0] = "liveCore"
	b.Bases[0].Automation.MaxBytes = 1 << 40
	again, err := j.Prepare(fence, journalID, now.Add(10*time.Second))
	if err != nil || again.Bases[0].Automation.AllowedActions[0] != "logs" || again.Bases[0].Automation.MaxBytes != 1024 {
		t.Fatal("caller changed an immutable pending automation acceptance", err)
	}
}

const journalID = "11111111-1111-4111-8111-111111111111"

func TestAutomationEnvelopeCannotMutateAnObservedJournal(t *testing.T) {
	_, snapshot, _, now := journalFixture(t)
	snapshot.Bindings[0].Automation = &authorization.AutomationEnvelope{AllowedActions: []string{"logs"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 1024}
	journal, err := NewBindingJournal(snapshot, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Bindings[0].Automation.AllowedActions[0] = "liveCore"
	snapshot.Bindings[0].Automation.MaxBytes = 1 << 40
	got := journal.byUID["binding"].Automation
	if got.AllowedActions[0] != "logs" || got.MaxBytes != 1024 {
		t.Fatal("caller widened retained automation envelope")
	}
}

func journalFixture(t *testing.T) (*BindingJournal, value.Snapshot, value.PermissionFence, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s := value.Snapshot{ClusterID: journalID, ControlNamespace: value.NamespaceRef{Name: "asservat", UID: "control"}, BindingResourceVersion: "list-rv", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	s.Bindings = []value.Binding{{Resource: value.Resource{ClusterID: journalID, Namespace: "asservat", NamespaceUID: "control", Kind: "AccessBinding", Name: "owners", UID: "binding", Generation: 1, ResourceVersion: "item-rv", SpecDigest: artifact.Digest{1}}, Scope: value.Scope{ClusterID: journalID, Namespace: value.NamespaceRef{Name: "payments", UID: "payments"}}, Effect: "Allow", Subjects: []value.Subject{{Kind: "Group", Issuer: "https://id.example.test", ID: "team-a"}}, Roles: []string{"workload-maintainer"}}}
	j, err := NewBindingJournal(s, now)
	if err != nil {
		t.Fatal(err)
	}
	return j, s, value.PermissionFence{RootID: journalID, Epoch: journalID, TrustDigest: artifact.Digest{2}, Initialized: true}, now
}
func journalAck(t *testing.T, j *BindingJournal, b value.PermissionBatch) value.PermissionFence {
	t.Helper()
	f := value.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, TrustDigest: b.TrustDigest, Sequence: b.ExpectedSequence + 1, Initialized: true}
	if err := j.Accepted(value.PermissionAcceptance{PermissionFence: f, AuditID: b.RequestID}); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestBindingJournalRequiresEveryOwnershipTransitionToBeAccepted(t *testing.T) {
	j, s, f, now := journalFixture(t)
	initial, err := j.Prepare(f, journalID, now)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Bases[0].Continuous {
		t.Fatal("relist asserted continuity")
	}
	f = journalAck(t, j, initial)
	b := cloneBinding(s.Bindings[0])
	b.Resource.ResourceVersion = "rv-b"
	b.Resource.Generation++
	b.Resource.SpecDigest[0]++
	b.Subjects[0].ID = "team-b"
	if err = j.Apply(value.BindingEvent{Type: "MODIFIED", ResourceVersion: "rv-b", Binding: &b}); err != nil {
		t.Fatal(err)
	}
	a := cloneBinding(b)
	a.Resource.ResourceVersion = "rv-a"
	a.Resource.Generation++
	a.Resource.SpecDigest[0]++
	a.Subjects[0].ID = "team-a"
	if err = j.Apply(value.BindingEvent{Type: "MODIFIED", ResourceVersion: "rv-a", Binding: &a}); err == nil {
		t.Fatal("intermediate ownership was skipped")
	}
	next, err := j.Prepare(f, "22222222-2222-4222-8222-222222222222", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next.Bases[0].Subjects[0].ID != "team-b" || !next.Bases[0].Continuous {
		t.Fatal("missing intermediate owner")
	}
	f = journalAck(t, j, next)
	if err = j.Apply(value.BindingEvent{Type: "MODIFIED", ResourceVersion: "rv-a", Binding: &a}); err != nil {
		t.Fatal(err)
	}
	final, err := j.Prepare(f, "33333333-3333-4333-8333-333333333333", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if final.ExpectedSequence != 2 || final.Bases[0].Subjects[0].ID != "team-a" {
		t.Fatal("return owner coalesced with original")
	}
}
func TestBindingJournalDoesNotRenewCompletenessFromBookmarkOrDifferentList(t *testing.T) {
	j, s, f, now := journalFixture(t)
	b, err := j.Prepare(f, journalID, now)
	if err != nil {
		t.Fatal(err)
	}
	f = journalAck(t, j, b)
	if err = j.Apply(value.BindingEvent{Type: "BOOKMARK", ResourceVersion: "new-bookmark"}); err != nil {
		t.Fatal(err)
	}
	changed := s
	changed.ObservedAt = now.Add(time.Second)
	changed.FreshUntil = now.Add(6 * time.Second)
	changed.Bindings = []value.Binding{cloneBinding(s.Bindings[0])}
	changed.Bindings[0].Resource.ResourceVersion = "not-processed"
	if err = j.Confirm(changed, now.Add(time.Second)); err == nil {
		t.Fatal("different relist asserted continuity")
	}
	if _, err = j.Prepare(f, "22222222-2222-4222-8222-222222222222", now.Add(5*time.Second)); err == nil {
		t.Fatal("bookmark renewed deny deadline")
	}
}
func TestBindingJournalKeepsPendingRequestForAmbiguousCommitAfterExpiry(t *testing.T) {
	j, _, f, now := journalFixture(t)
	b, err := j.Prepare(f, journalID, now)
	if err != nil {
		t.Fatal(err)
	}
	b.Bases[0].Subjects[0].ID = "mutated-caller-copy"
	again, err := j.Prepare(f, journalID, now.Add(10*time.Second))
	if err != nil {
		t.Fatalf("cannot resolve an ambiguous original commit: %v", err)
	}
	if again.Bases[0].Subjects[0].ID != "team-a" || !again.ObservedAt.Equal(now) || !again.FreshUntil.Equal(now.Add(5*time.Second)) {
		t.Fatal("replay mutated request or renewed deadline")
	}
}
