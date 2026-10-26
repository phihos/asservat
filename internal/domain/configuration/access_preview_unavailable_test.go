package configuration

import (
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
)

// Gitar review of #77: an object whose assignments are hidden by an
// unavailable cell outside a workload-narrowed envelope cannot be proven to
// lie inside it, so the reply equals the reply for a nonexistent UID.
func TestPreviewUnavailableForeignCellIndistinguishable(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	narrow := []PreviewEnvelope{payments("wl-1")}
	inside := previewCell(now, "wl-1")
	inside.Projection.Allows = nil
	hidden := previewCell(now, "wl-2")
	hidden.Unavailable, hidden.Projection = authorization.UnmetPermissionStale, authorization.Projection{}
	cells := []PreviewCell{inside, hidden}
	for _, change := range []AccessChange{
		{Action: "delete", Kind: "AccessBinding", UID: "binding-x"},
		{Action: "update", Kind: "AccessBinding", UID: "binding-x", Binding: previewBinding("Deny", "team-a", "wl-1")},
	} {
		changes, _, err := PreviewChanges([]AccessChange{change}, narrow)
		if err != nil {
			t.Fatal(err)
		}
		found, err1 := PreviewAccess(changes, PreviewSnapshot{Cells: cells}, []string{previewCluster}, narrow, previewPolicy, now)
		absent, err2 := PreviewAccess(changes, PreviewSnapshot{Cells: cells, Unmatched: []PreviewBasis{{"AccessBinding", "binding-x"}}}, []string{previewCluster}, narrow, previewPolicy, now)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(found, absent) || len(found.Unmatched) != 1 {
			t.Fatalf("%s distinguishable:\n%+v\n%+v", change.Action, found, absent)
		}
	}
	// Any unavailable cell also withholds removal of an in-envelope object;
	// with every cell read, the same object is removed and evaluated.
	cell := previewCell(now, "wl-1")
	cell.Projection.Allows[0].Audience.BasisUID = "binding-x"
	changes, _, _ := PreviewChanges([]AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "binding-x"}}, narrow)
	got, err := PreviewAccess(changes, PreviewSnapshot{Cells: []PreviewCell{cell, hidden}}, []string{previewCluster}, narrow, previewPolicy, now)
	if err != nil || got.DeltasTotal != 0 || len(got.Unmatched) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
	got, err = PreviewAccess(changes, PreviewSnapshot{Cells: []PreviewCell{cell}}, []string{previewCluster}, narrow, previewPolicy, now)
	if err != nil || got.DeltasTotal != 3 || len(got.Unmatched) != 0 {
		t.Fatalf("proven in-envelope delete: %v %+v", err, got)
	}
}
