package configuration

import (
	"errors"
	"reflect"
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

// A PermissionSource create/update changes no accepted assignment in this
// installation: it is reported Indeterminate and the preview is incomplete.
func TestPreviewSourceNotEvaluated(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	source := Source{Resource: Resource{SpecDigest: artifact.Digest{5}}, Type: "namespaceMetadata", ClusterID: previewCluster, Enabled: true}
	got := runPreview(t, []AccessChange{{Action: "create", Kind: "PermissionSource", Source: source}}, previewCell(now, "wl-1"))
	if got.Complete() || len(got.NotEvaluated) != 1 || len(got.Deltas) != 0 {
		t.Fatalf("%+v", got)
	}
}

func payments(workloads ...string) PreviewEnvelope {
	e := PreviewEnvelope{Scope: Scope{ClusterID: previewCluster, Namespace: NamespaceRef{Name: "payments", UID: "ns-uid"}}, Roles: []string{"workload-maintainer", "evidence-reader"}, Issuers: []string{previewIssuer}}
	for _, w := range workloads {
		e.Scope.Workloads = append(e.Scope.Workloads, WorkloadRef{Kind: "Deployment", Name: "api", UID: w})
	}
	return e
}

// A delegated writer previews only objects the native guard would admit for
// them, and sees only the cells inside their envelope.
func TestPreviewDelegatedEnvelope(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cells := PreviewSnapshot{Cells: []PreviewCell{previewCell(now, "wl-1"), previewCell(now, OtherWorkloads)}}
	narrow := []PreviewEnvelope{payments("wl-1")}
	inside := AccessChange{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Deny", "team-a", "wl-1")}
	changes, _, err := PreviewChanges([]AccessChange{inside}, narrow)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PreviewAccess(changes, cells, []string{previewCluster}, narrow, previewPolicy, now)
	if err != nil || got.Targets != 1 || got.DeltasTotal != 3 || got.Deltas[0].Target.WorkloadUID != "wl-1" {
		t.Fatalf("%v %+v", err, got)
	}
	other := previewBinding("Deny", "team-a", "wl-1")
	other.Scope.Namespace.UID = "other-ns"
	automation := previewBinding("Allow", "team-a", "wl-1")
	automation.Automation = &authorization.AutomationEnvelope{}
	foreignRole := previewBinding("Allow", "team-a", "wl-1")
	foreignRole.Roles = []string{"action-approver"}
	foreignIssuer := previewBinding("Allow", "team-a", "wl-1")
	foreignIssuer.Subjects[0].Issuer = "https://other.example.invalid"
	for _, refused := range []AccessChange{
		{Action: "create", Kind: "AccessBinding", Binding: previewBinding("Deny", "team-a")},
		{Action: "create", Kind: "AccessBinding", Binding: other},
		{Action: "create", Kind: "AccessBinding", Binding: automation},
		{Action: "create", Kind: "AccessBinding", Binding: foreignRole},
		{Action: "create", Kind: "AccessBinding", Binding: foreignIssuer},
		{Action: "delete", Kind: "PermissionSource", UID: "source"},
	} {
		if _, _, err := PreviewChanges([]AccessChange{refused}, narrow); !errors.Is(err, ErrDenied) {
			t.Fatalf("%+v: %v", refused, err)
		}
	}
	// binding-a is namespace-wide: deleting it touches the namespace's other
	// workloads, which a workload-narrowed envelope does not cover. It is
	// reported exactly like a UID that does not exist (Gitar review on #77):
	// same reply, nothing removed.
	changes, read, err := PreviewChanges([]AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "binding-a"}}, narrow)
	if err != nil || len(read.Allowed) != 1 || read.Allowed[0] != (PreviewNamespace{previewCluster, "ns-uid"}) || len(read.Namespaces) != 1 {
		t.Fatalf("%v %+v", err, read)
	}
	foreign, err := PreviewAccess(changes, cells, []string{previewCluster}, narrow, previewPolicy, now)
	if err != nil {
		t.Fatal(err)
	}
	absentChanges, _, _ := PreviewChanges([]AccessChange{{Action: "delete", Kind: "AccessBinding", UID: "binding-a"}}, narrow)
	absent, err := PreviewAccess(absentChanges, PreviewSnapshot{Cells: cells.Cells, Unmatched: []PreviewBasis{{"AccessBinding", "binding-a"}}}, []string{previewCluster}, narrow, previewPolicy, now)
	if err != nil || !reflect.DeepEqual(foreign, absent) || len(foreign.Unmatched) != 1 || foreign.DeltasTotal != 0 {
		t.Fatalf("foreign UID distinguishable from a nonexistent one:\n%+v\n%+v", foreign, absent)
	}
	// An update of such an object adds its proposed rows like an update of a
	// nonexistent UID would.
	update := []AccessChange{{Action: "update", Kind: "AccessBinding", UID: "binding-a", Binding: previewBinding("Deny", "team-a", "wl-1")}}
	updateChanges, _, _ := PreviewChanges(update, narrow)
	foreign, err1 := PreviewAccess(updateChanges, cells, []string{previewCluster}, narrow, previewPolicy, now)
	absent, err2 := PreviewAccess(updateChanges, PreviewSnapshot{Cells: cells.Cells, Unmatched: []PreviewBasis{{"AccessBinding", "binding-a"}}}, []string{previewCluster}, narrow, previewPolicy, now)
	if err1 != nil || err2 != nil || !reflect.DeepEqual(foreign, absent) || foreign.DeltasTotal != 3 {
		t.Fatalf("update distinguishable:\n%+v\n%+v", foreign, absent)
	}
	wide := []PreviewEnvelope{payments()}
	if got, err := PreviewAccess(changes, cells, []string{previewCluster}, wide, previewPolicy, now); err != nil || got.Targets != 2 || got.DeltasTotal != 6 {
		t.Fatalf("namespace envelope: %v %+v", err, got)
	}
}
