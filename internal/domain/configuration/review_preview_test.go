package configuration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// ADR-245: deleting a decision-time source removes the persistent
// assignments it minted. A current allowed decision shows Allow -> Deny; an
// assignment without one shows Indeterminate (DecisionTimeSource) -> Deny.
func TestPreviewDeletingDecisionTimeSourceRemovesItsAssignments(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cell := previewCell(now, "workload-a")
	reviewed := func(subject, id string) artifact.AudienceAssignment {
		return artifact.AudienceAssignment{Kind: "User", Issuer: previewIssuer, SubjectID: subject, Role: "workload-maintainer", BasisKind: "PermissionSource", BasisUID: "exec-source", BasisDigest: artifact.Digest{4}, AssignmentID: id}
	}
	cell.Projection.Allows = append(cell.Projection.Allows, authorization.CurrentAssignment{Audience: reviewed("alice", "33333333-3333-3333-3333-333333333333"), ObservedAt: now, FreshUntil: now.Add(20 * time.Second), Reviewed: true})
	cell.Unknown = []artifact.AudienceAssignment{reviewed("bob", "44444444-4444-4444-4444-444444444444")}
	out := runPreview(t, []AccessChange{{Action: "delete", Kind: "PermissionSource", UID: "exec-source"}}, cell)
	alice, bob := deltasFor(out, "alice"), deltasFor(out, "bob")
	for _, op := range previewOperations {
		if d, ok := alice[op]; !ok || d.Before != authorization.Allow || d.After != authorization.Deny {
			t.Fatalf("current decision not shown as removed for %s: %+v", op, d)
		}
		if d, ok := bob[op]; !ok || d.Before != authorization.Indeterminate || d.BeforeUnmet != DecisionTimeSource || d.After != authorization.Deny {
			t.Fatalf("unknown decision not Indeterminate before for %s: %+v", op, d)
		}
	}
	if d := deltasFor(out, "team-a"); len(d) != 0 {
		t.Fatal("unrelated binding changed", d)
	}
	// Deleting an unrelated binding leaves the review rows untouched.
	if out := runPreview(t, []AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "other"}}, cell); len(deltasFor(out, "bob")) != 0 || len(deltasFor(out, "alice")) != 0 {
		t.Fatal("unrelated change touched decision-time assignments")
	}
}
