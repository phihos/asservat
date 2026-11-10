package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestProcessingInventoryPageRetainsFiniteImmutableRuleScopes(t *testing.T) {
	const id = "10000000-0000-4000-8000-000000000001"
	n := time.Now().UTC().Truncate(time.Microsecond)
	rule := ProcessingInventoryRule{ID: id, State: "reserved", Scope: ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}}, AdministrationUntil: n.Add(time.Hour), RetireBy: n.Add(2 * time.Hour)}
	q := ProcessingInventoryQuery{Limit: 1}
	page := ProcessingInventoryPage{RootID: id, Epoch: id, Initialized: false, Sequence: 1, Rules: []ProcessingInventoryRule{rule}, NextCursor: id, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}
	if !page.Valid(q, n) {
		t.Fatal("reserved original rule cannot be listed")
	}
	for _, mutate := range []func(*ProcessingInventoryPage){func(p *ProcessingInventoryPage) { p.Rules = append(p.Rules, p.Rules[0]) }, func(p *ProcessingInventoryPage) { p.Rules[0].State = "released" }, func(p *ProcessingInventoryPage) { p.ValidUntil = n.Add(6 * time.Second) }, func(p *ProcessingInventoryPage) { p.NextCursor = "20000000-0000-4000-8000-000000000002" }} {
		copied := page
		copied.Rules = append([]ProcessingInventoryRule(nil), page.Rules...)
		mutate(&copied)
		if copied.Valid(q, n) {
			t.Fatal("invalid page accepted", copied)
		}
	}
	if page.Valid(ProcessingInventoryQuery{After: id, Limit: 1}, n) || page.Valid(ProcessingInventoryQuery{Limit: 101}, n) {
		t.Fatal("cursor or maximum ignored")
	}
	change := ProcessingChange{Action: "release_processing", RequestID: id, RuleID: id, ExpectedRevision: 1, RequestedArtifactID: id}
	if change.ValidRequest() {
		t.Fatal("release accepted a selector instead of immutable scope")
	}
}
