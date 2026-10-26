package configuration

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	previewIssuer  = "https://id.example.invalid"
	previewCluster = "11111111-1111-1111-1111-111111111111"
)

var previewPolicy = identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}

// previewCell is one workload cell whose accepted projection gives group
// team-a workload-maintainer through AccessBinding binding-a.
func previewCell(now time.Time, workload string) PreviewCell {
	target := authorization.Target{ClusterID: previewCluster, NamespaceUID: "ns-uid", WorkloadUID: workload, PodUID: workload}
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: previewIssuer, SubjectID: "team-a", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-a", BasisDigest: artifact.Digest{1}, AssignmentID: "22222222-2222-2222-2222-222222222222"}
	p := authorization.Projection{Target: target, Revision: previewPolicy, ObservedAt: now, FreshUntil: now.Add(20 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(20 * time.Second),
		Allows: []authorization.CurrentAssignment{{Audience: a, ObservedAt: now, FreshUntil: now.Add(20 * time.Second)}}}
	return PreviewCell{Target: target, Projection: p}
}

func previewBinding(effect, group string, workloads ...string) Binding {
	b := Binding{Resource: Resource{SpecDigest: artifact.Digest{9}}, Effect: effect, Subjects: []Subject{{"Group", previewIssuer, group}}, Roles: []string{"workload-maintainer"},
		Scope: Scope{ClusterID: previewCluster, Namespace: NamespaceRef{Name: "payments", UID: "ns-uid"}}}
	for _, w := range workloads {
		b.Scope.Workloads = append(b.Scope.Workloads, WorkloadRef{Kind: "Deployment", Name: "api", UID: w})
	}
	return b
}

func runPreview(t *testing.T, changes []AccessChange, cells ...PreviewCell) AccessPreview {
	t.Helper()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	changes, _, err := PreviewChanges(changes, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := PreviewAccess(changes, PreviewSnapshot{Cells: cells}, []string{previewCluster}, nil, previewPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func deltasFor(p AccessPreview, subject string) map[authorization.Operation]AccessDelta {
	out := map[authorization.Operation]AccessDelta{}
	for _, d := range p.Deltas {
		if d.Subject.ID == subject {
			out[d.Operation] = d
		}
	}
	return out
}

// ADR-237: a proposed deny is evaluated by the real evaluator and turns the
// group's current Allow into Deny/ExplicitDeny for every operation its role
// grants.
func TestPreviewAddedDeny(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	got := runPreview(t, []AccessChange{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Deny", "team-a")}}, previewCell(now, "wl-1"))
	d := deltasFor(got, "team-a")
	if len(d) != 3 || got.DeltasTotal != 3 || !got.Complete() {
		t.Fatalf("deltas %+v", got)
	}
	for _, op := range previewOperations {
		if d[op].Before != authorization.Allow || d[op].After != authorization.Deny || d[op].AfterUnmet != authorization.UnmetExplicitDeny {
			t.Fatalf("%s: %+v", op, d[op])
		}
	}
}

// Removing the only allow takes the group from Allow to Deny/NoMatchingAllow;
// an unrelated group in the same projection does not appear.
func TestPreviewRemovedAllow(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cell := previewCell(now, "wl-1")
	other := cell.Projection.Allows[0]
	other.Audience.SubjectID, other.Audience.BasisUID, other.Audience.AssignmentID = "team-b", "binding-b", "33333333-3333-3333-3333-333333333333"
	cell.Projection.Allows = append(cell.Projection.Allows, other)
	got := runPreview(t, []AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "binding-a"}}, cell)
	d := deltasFor(got, "team-a")
	if len(d) != 3 || len(deltasFor(got, "team-b")) != 0 {
		t.Fatalf("deltas %+v", got.Deltas)
	}
	if x := d[authorization.CollectContext]; x.Before != authorization.Allow || x.After != authorization.Deny || x.AfterUnmet != authorization.UnmetNoMatchingAllow {
		t.Fatalf("%+v", x)
	}
}

// An update replaces the object's assignments: narrowing binding-a to one
// workload removes the group's access from the namespace's other workloads
// only.
func TestPreviewUpdateNarrowsScope(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	named, rest := previewCell(now, "wl-1"), previewCell(now, OtherWorkloads)
	got := runPreview(t, []AccessChange{{Action: "update", Kind: "AccessBinding", UID: "binding-a", Binding: previewBinding("Allow", "team-a", "wl-1")}}, named, rest)
	if got.DeltasTotal != 3 || got.Targets != 2 {
		t.Fatalf("%+v", got)
	}
	for _, d := range got.Deltas {
		if d.Target.WorkloadUID != OtherWorkloads || d.After != authorization.Deny {
			t.Fatalf("only the unnamed workloads lose access: %+v", d)
		}
	}
}

// Unavailable projections and clusters outside the installation are reported
// Indeterminate and never evaluated, so they can never show Allow.
func TestPreviewUnavailableClusterIsIndeterminate(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	stale := previewCell(now, "wl-1")
	stale.Unavailable = authorization.UnmetPermissionStale
	foreign := previewCell(now, "wl-2")
	foreign.Target.ClusterID = "99999999-9999-9999-9999-999999999999"
	got := runPreview(t, []AccessChange{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Allow", "team-c")}}, stale, foreign)
	if got.Complete() || len(got.Unavailable) != 2 || len(got.Deltas) != 0 || got.DeltasTotal != 0 {
		t.Fatalf("%+v", got)
	}
	if got.Unavailable[1].Unavailable != ClusterUnavailable || len(got.Unavailable[0].Projection.Allows) != 0 {
		t.Fatalf("unavailable cells %+v", got.Unavailable)
	}
}

// A stale accepted projection keeps the evaluator's Indeterminate on both
// sides: a proposed allow cannot report Allow over stale permission data.
func TestPreviewStaleProjectionNeverAllows(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cell := previewCell(now, "wl-1")
	cell.Projection.DeniesFreshUntil = now.Add(-time.Second)
	got := runPreview(t, []AccessChange{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Allow", "team-c")}}, cell)
	if len(got.Deltas) != 0 {
		t.Fatalf("stale projection produced a delta: %+v", got.Deltas)
	}
}

func TestPreviewBounds(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	change := AccessChange{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Allow", "team-c")}
	many := make([]AccessChange, MaxPreviewChanges+1)
	for n := range many {
		many[n] = change
	}
	if _, _, err := PreviewChanges(many, nil); !errors.Is(err, ErrLimit) {
		t.Fatalf("17 changes: %v", err)
	}
	cells := make([]PreviewCell, MaxPreviewTargets+1)
	for n := range cells {
		cells[n] = previewCell(now, "wl")
	}
	changes, _, _ := PreviewChanges([]AccessChange{change}, nil)
	if _, err := PreviewAccess(changes, PreviewSnapshot{Cells: cells}, []string{previewCluster}, nil, previewPolicy, now); !errors.Is(err, ErrLimit) {
		t.Fatalf("1,001 targets: %v", err)
	}
	for _, bad := range [][]AccessChange{
		{{Action: "create", Kind: "PermissionSource", Binding: previewBinding("Allow", "x")}},
		{{Action: "update", Kind: "AccessBinding", Binding: previewBinding("Allow", "x")}},
		{{Action: "delete", Kind: "AccessBinding", UID: "a"}, {Action: "update", Kind: "AccessBinding", UID: "a", Binding: previewBinding("Allow", "x")}},
		{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Allow", "x", OtherWorkloads)}},
	} {
		if _, _, err := PreviewChanges(bad, nil); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", bad, err)
		}
	}
}
