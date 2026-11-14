package configuration

import (
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

// Every delta is retained up to the memory bound and counted; the reply's
// 256 KiB bound is applied when it is serialized.
func TestPreviewDeltasCounted(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var cells []PreviewCell
	for n := range 30 {
		cells = append(cells, previewCell(now, "wl-"+string(rune('a'+n))))
	}
	got := runPreview(t, []AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "binding-a"}}, cells...)
	if got.DeltasTotal != 90 || len(got.Deltas) != 90 || !got.FreshUntil.Equal(now.Add(20*time.Second)) {
		t.Fatalf("total %d rows %d fresh %v", got.DeltasTotal, len(got.Deltas), got.FreshUntil)
	}
}

// Each delta names the assignments that decided it: the removed allow before,
// the proposed deny (with the proposal's spec digest) after.
func TestPreviewDeltaRevisions(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	got := runPreview(t, []AccessChange{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Deny", "team-a")}}, previewCell(now, "wl-1"))
	d := got.Deltas[0]
	if len(d.BeforeBasis) != 1 || d.BeforeBasis[0].Proposed || d.BeforeBasis[0].Assignment.BasisUID != "binding-a" || d.BeforeBasis[0].Effect != "allow" {
		t.Fatalf("before %+v", d.BeforeBasis)
	}
	if len(d.AfterBasis) != 1 || !d.AfterBasis[0].Proposed || d.AfterBasis[0].Effect != "deny" || d.AfterBasis[0].Assignment.BasisDigest != (artifact.Digest{9}) || d.AfterBasis[0].Assignment.BasisUID != "proposed-1" {
		t.Fatalf("after %+v", d.AfterBasis)
	}
	allow := runPreview(t, []AccessChange{{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Allow", "team-c")}}, previewCell(now, "wl-1"))
	if a := allow.Deltas[0]; a.After != authorization.Allow || a.AfterValidUntil.IsZero() || len(a.AfterBasis) != 1 || !a.AfterBasis[0].Proposed {
		t.Fatalf("allow %+v", a)
	}
}

func previewSource(uid string) Source {
	return Source{Resource: Resource{Kind: "PermissionSource", UID: uid, SpecDigest: artifact.Digest{5}}, Type: "namespaceMetadata", ClusterID: previewCluster, Enabled: true, Role: "evidence-reader"}
}

func sourceGrant(groups ...string) []NamespaceGrant {
	g := NamespaceGrant{Namespace: NamespaceRef{Name: "payments", UID: "ns-uid"}}
	for _, id := range groups {
		g.Subjects = append(g.Subjects, Subject{"Group", previewIssuer, id})
	}
	return []NamespaceGrant{g}
}

// sourceCell is a cell whose projection also holds team-s evidence-reader
// through the accepted source source-a.
func sourceCell(now time.Time, workload string) PreviewCell {
	c := previewCell(now, workload)
	a := artifact.AudienceAssignment{Kind: "Group", Issuer: previewIssuer, SubjectID: "team-s", Role: "evidence-reader", BasisKind: "PermissionSource", BasisUID: "source-a", BasisDigest: artifact.Digest{4}, AssignmentID: "33333333-3333-3333-3333-333333333333"}
	c.Projection.Allows = append(c.Projection.Allows, authorization.CurrentAssignment{Audience: a, ObservedAt: now, FreshUntil: now.Add(20 * time.Second)})
	return c
}

func runSourcePreview(t *testing.T, change AccessChange, grants PreviewSourceGrants, cells ...PreviewCell) AccessPreview {
	t.Helper()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	changes, read, err := PreviewChanges([]AccessChange{change})
	if err != nil || len(read.Sources) != 1 || read.Sources[0].Resource.UID != change.Source.Resource.UID && change.UID == "" && read.Sources[0].Resource.UID != "proposed-1" {
		t.Fatalf("%v %+v", err, read)
	}
	out, err := PreviewAccess(changes, PreviewSnapshot{Cells: cells, Sources: []PreviewSourceGrants{grants}}, []string{previewCluster}, previewPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ADR-242: a proposed source is evaluated through the namespace grants the
// accepted observation yields for it: its groups gain the source's role in
// every workload cell of each granted namespace, with the proposed revision.
func TestPreviewSourceCreateGrantsNamespaceWide(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	got := runSourcePreview(t, AccessChange{Action: "create", Kind: "PermissionSource", Source: previewSource("")}, PreviewSourceGrants{Grants: sourceGrant("team-n")},
		previewCell(now, "wl-1"), previewCell(now, OtherWorkloads))
	if !got.Complete() || got.DeltasTotal != 4 {
		t.Fatalf("%+v", got)
	}
	for _, d := range got.Deltas {
		if d.Subject.ID != "team-n" || d.Operation == authorization.CollectContext || d.Before != authorization.Deny || d.After != authorization.Allow ||
			len(d.AfterBasis) != 1 || !d.AfterBasis[0].Proposed || d.AfterBasis[0].Assignment.BasisKind != "PermissionSource" || d.AfterBasis[0].Assignment.BasisUID != "proposed-1" || d.AfterBasis[0].Assignment.BasisDigest != (artifact.Digest{5}) {
			t.Fatalf("%+v", d)
		}
	}
}

// An updated source replaces its current assignments with its new grants;
// a source granting nothing removes them.
func TestPreviewSourceUpdateReplacesAssignments(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	got := runSourcePreview(t, AccessChange{Action: "update", Kind: "PermissionSource", UID: "source-a", Source: previewSource("")}, PreviewSourceGrants{}, sourceCell(now, "wl-1"))
	if !got.Complete() || got.DeltasTotal != 2 || deltasFor(got, "team-s")[authorization.ReadApproved].After != authorization.Deny {
		t.Fatalf("%+v", got)
	}
	got = runSourcePreview(t, AccessChange{Action: "update", Kind: "PermissionSource", UID: "source-a", Source: previewSource("")}, PreviewSourceGrants{Grants: sourceGrant("team-s")}, sourceCell(now, "wl-1"))
	if got.DeltasTotal != 0 {
		t.Fatalf("unchanged grant reported a change: %+v", got.Deltas)
	}
}

// Unknown namespace metadata makes a source change Indeterminate: it is
// listed, never evaluated, and an updated source's current assignments stay.
func TestPreviewSourceWithoutObservationIsIndeterminate(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	for _, reason := range []string{MetadataUnavailable, MetadataNotObserved} {
		got := runSourcePreview(t, AccessChange{Action: "update", Kind: "PermissionSource", UID: "source-a", Source: previewSource("")}, PreviewSourceGrants{Unevaluated: reason}, sourceCell(now, "wl-1"))
		if got.Complete() || len(got.NotEvaluated) != 1 || got.NotEvaluated[0].Unevaluated != reason || got.DeltasTotal != 0 {
			t.Fatalf("%s: %+v", reason, got)
		}
	}
	changes, _, _ := PreviewChanges([]AccessChange{{Action: "create", Kind: "PermissionSource", Source: previewSource("")}})
	if _, err := PreviewAccess(changes, PreviewSnapshot{Cells: []PreviewCell{previewCell(now, "wl-1")}}, []string{previewCluster}, previewPolicy, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("snapshot without the source's grants accepted", err)
	}
}
