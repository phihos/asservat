package capture

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"testing"
	"time"
)

// Reuses the stable synthetic app authority/source ports. This checks passive
// selection composition, not installed101-source resource/clock qualification.
func crossBatchSaveFixture(t *testing.T, count int) (*inventoryFixture, RecordingSaves, *manualSaveCaller, *groupPreviewFixture) {
	t.Helper()
	x, inv, _, _ := newRecordingInventoryFixture(t, count)
	f := x.f
	current := &manualSaveCaller{f: f, actor: f.actor}
	team, _, settings, _ := newTeamRecordingFixture(t)
	f.audience = team.audience
	f.cap.ExecutionClass = artifact.ContextAPIExecution
	f.svc.Approvals = settings
	accepted := inv.Accepted
	f.svc.Eligibility = authapp.CaptureEligibility{Human: authapp.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Accepted: accepted, Current: accepted.(*teamRecordingAuthority), Now: func() time.Time { return f.now }}
	x.policy.Policy.IncidentPods = 2
	x.policy.Policy.ObservedPods = targets.MaxRestartPods
	if !x.policy.Policy.Valid() || x.policy.Policy.ObservedPods < 101 {
		t.Fatal("fixture lacks legal cross-batch observation scope")
	}
	for n := range x.rows {
		source := &x.rows[n].Source
		source.Audience = []artifact.AudienceAssignment{f.audience}
		digest, _ := compiler.SourceAudienceDigest(source.Audience)
		source.Binding.AudienceDigest = [32]byte(digest)
		source.StartedAt = f.now.Add(-time.Second)
		source.Target.BindingDigest = deliveryapp.SourceBindingDigest(source.Binding)
	}
	fixture := &groupPreviewFixture{investigationFixture: f}
	f.svc.Targets = fixture
	f.svc.Previews = fixture
	f.svc.RecordingGroups = fixture
	f.svc.RecordingSources = x
	f.svc.PolicyAccepted = accepted
	f.svc.RecordingPolicies = x
	f.svc.RecordingSaveEnabled = true
	return x, RecordingSaves{Inventory: inv, Investigation: f.svc}, current, fixture
}
func TestRecordingSaveSelectsValidSamePolicyHandlesAcrossInventoryBatches(t *testing.T) {
	x, service, current, fixture := crossBatchSaveFixture(t, 101)
	original := x.rows[0].Source.Target.Target()
	target := authorization.WorkloadTarget{ClusterID: original.ClusterID, NamespaceUID: original.NamespaceUID, WorkloadUID: original.WorkloadUID}
	first, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil || len(first.Rows) != 100 || first.Cursor == "" {
		t.Fatal("first100-source batch", err, len(first.Rows))
	}
	second, err := service.Inventory.List(t.Context(), current, target, "", first.Cursor, 100)
	if err != nil || len(second.Rows) != 1 || x.writes != 2 || !second.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("last source original-expiry batch", err, len(second.Rows), x.writes)
	}
	handles := []string{first.Rows[0].Handle, second.Rows[0].Handle}
	actor, err := current.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string]bool{}
	for _, handle := range handles {
		id, _, ok := value.ParseRecordingHandle(handle)
		if !ok {
			t.Fatal("bad inventory handle")
		}
		set, err := service.Inventory.Selections.ReadRecordingSelection(t.Context(), actor.Principal, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = set.Select(actor.Principal, []string{handle}, x.f.now); err != nil {
			t.Fatal("individual current handle invalid", err)
		}
		sets[id] = true
	}
	if len(sets) != 2 {
		t.Fatal("test did not crossprotected selection sets")
	}
	preview, err := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles, Before: time.Second})
	if err != nil {
		t.Fatal("two individually valid same-policy/workload handles cannot formoneSave", err)
	}
	if preview.Preview.Group == nil || len(preview.Preview.Group.Children) != 2 || len(preview.RecordingSave.Selected) != 2 || fixture.groups != 1 {
		t.Fatal("cross-batch selection was dropped or split", fixture.groups)
	}
	for id := range sets {
		set := x.sets[id]
		if !set.ExpiresAt.Equal(first.ExpiresAt) {
			t.Fatal("preview rewrote original inventory set", id, set.ExpiresAt)
		}
	}
}
func TestRecordingSaveProtectedReviewKeepsOwnLifetimeWithoutRenewingInventorySet(t *testing.T) {
	x, service, current, _ := crossBatchSaveFixture(t, 2)
	x.policy.Policy.Recorder.Action.Timeout = "2m"
	x.policy.Policy.Recorder.Composition.MaxDuration = "2m"
	if !x.policy.Policy.Valid() {
		t.Fatal("legal original finalize interval required")
	}
	original := x.rows[0].Source.Target.Target()
	target := authorization.WorkloadTarget{ClusterID: original.ClusterID, NamespaceUID: original.NamespaceUID, WorkloadUID: original.WorkloadUID}
	page, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil || len(page.Rows) != 2 {
		t.Fatal("original selection", err)
	}
	x.f.now = x.f.now.Add(2 * time.Second)
	preview, err := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: []string{page.Rows[0].Handle, page.Rows[1].Handle}, Before: time.Second})
	if err != nil {
		t.Fatal("still-current original handles", err)
	}
	id, _, _ := value.ParseRecordingHandle(page.Rows[0].Handle)
	if !x.sets[id].ExpiresAt.Equal(page.ExpiresAt) || !preview.Preview.SelectionUntil.After(page.ExpiresAt) || preview.Preview.SelectionUntil.After(preview.Preview.CreatedAt.Add(time.Minute)) {
		t.Fatal("protected review lost its own lifetime or renewed inventory", preview.Preview.SelectionUntil, page.ExpiresAt)
	}
}

func TestRecordingSaveCombinesCurrentHandlesFromIndependentInventorySets(t *testing.T) {
	x, service, current, _ := crossBatchSaveFixture(t, 2)
	x.policy.Policy.ObservedPods = 2
	original := x.rows[0].Source.Target.Target()
	target := authorization.WorkloadTarget{ClusterID: original.ClusterID, NamespaceUID: original.NamespaceUID, WorkloadUID: original.WorkloadUID}
	old, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil || len(old.Rows) != 2 {
		t.Fatal(err)
	}
	x.f.now = x.f.now.Add(time.Second)
	fresh, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil || len(fresh.Rows) != 2 || x.writes != 2 {
		t.Fatal("independent current inventory", err, x.writes)
	}
	oldID, _, _ := value.ParseRecordingHandle(old.Rows[0].Handle)
	newID, _, _ := value.ParseRecordingHandle(fresh.Rows[1].Handle)
	if oldID == newID || !fresh.ExpiresAt.After(old.ExpiresAt) {
		t.Fatal("fixture didnotcreate distinctoriginal lifetimes")
	}
	preview, err := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: []string{old.Rows[0].Handle, fresh.Rows[1].Handle}, Before: time.Second})
	if err != nil {
		t.Fatal("valid handles from two current inventory requests rejected", err)
	}
	if preview.Preview.Group == nil || len(preview.Preview.Group.Children) != 2 || !x.sets[oldID].ExpiresAt.Equal(old.ExpiresAt) || !x.sets[newID].ExpiresAt.Equal(fresh.ExpiresAt) {
		t.Fatal("cross-set conversion changed cohort or original lifetimes")
	}
}

type crossBatchSelectionStore struct {
	*inventoryFixture
	reads []string
	after func(int)
}

func (s *crossBatchSelectionStore) ReadRecordingSelection(ctx context.Context, actor identity.Principal, id string) (value.RecordingSelectionSet, error) {
	s.reads = append(s.reads, id)
	set, err := s.inventoryFixture.ReadRecordingSelection(ctx, actor, id)
	if s.after != nil {
		s.after(len(s.reads))
	}
	return set, err
}
func TestRecordingSaveCrossSetValidationRejectsMixedExpiredAndDuplicateSelections(t *testing.T) {
	for _, kind := range []string{"policy", "scope", "target", "root", "client", "expired", "duplicate handle", "duplicate source", "expires during later read"} {
		t.Run(kind, func(t *testing.T) {
			x, service, current, fixture := crossBatchSaveFixture(t, 2)
			original := x.rows[0].Source.Target.Target()
			target := authorization.WorkloadTarget{ClusterID: original.ClusterID, NamespaceUID: original.NamespaceUID, WorkloadUID: original.WorkloadUID}
			first, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
			if err != nil {
				t.Fatal(err)
			}
			second, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
			if err != nil {
				t.Fatal(err)
			}
			handles := []string{first.Rows[0].Handle, second.Rows[1].Handle}
			id, _, _ := value.ParseRecordingHandle(second.Rows[1].Handle)
			set := x.sets[id]
			switch kind {
			case "policy":
				set.References[1].PolicyUID = "other-policy"
			case "scope":
				set.References[1].ExecutionDigest = artifact.Digest{99}
			case "target":
				set.Target.WorkloadUID = "other-workload"
			case "root":
				set.RootID = fixtureID(9998)
			case "client":
				set.Actor.ClientID = "another-client"
			case "expired":
				set.CreatedAt = x.f.now.Add(-time.Minute)
				set.ExpiresAt = x.f.now.Add(-time.Microsecond)
			case "duplicate handle":
				handles[1] = handles[0]
			case "duplicate source":
				handles[1] = second.Rows[0].Handle
			}
			x.sets[id] = set
			store := &crossBatchSelectionStore{inventoryFixture: x}
			service.Inventory.Selections = store
			if kind == "expires during later read" {
				firstID, _, _ := value.ParseRecordingHandle(handles[0])
				firstSet := x.sets[firstID]
				firstSet.ExpiresAt = x.f.now.Add(time.Millisecond)
				x.sets[firstID] = firstSet
				store.after = func(n int) {
					if n == 2 {
						x.f.now = x.f.now.Add(2 * time.Millisecond)
					}
				}
			}
			sourceReads := x.reads
			selectionWrites := x.writes
			if _, err = service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles, Before: time.Second}); err == nil {
				t.Fatal("invalid cross-set selection accepted", kind)
			}
			if fixture.groups != 0 || x.reads != sourceReads || x.writes != selectionWrites {
				t.Fatal("invalidselection queried sources or persisted preview", kind, fixture.groups, x.reads-sourceReads, x.writes-selectionWrites)
			}
		})
	}
}
func TestRecordingSaveCrossSetReadsEachSetOnceAndPreservesHandleOrder(t *testing.T) {
	x, service, current, _ := crossBatchSaveFixture(t, 16)
	original := x.rows[0].Source.Target.Target()
	target := authorization.WorkloadTarget{ClusterID: original.ClusterID, NamespaceUID: original.NamespaceUID, WorkloadUID: original.WorkloadUID}
	first, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Inventory.List(t.Context(), current, target, "", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	handles := []string{}
	for i := 15; i >= 0; i-- {
		if i%2 == 0 {
			handles = append(handles, first.Rows[i].Handle)
		} else {
			handles = append(handles, second.Rows[i].Handle)
		}
	}
	store := &crossBatchSelectionStore{inventoryFixture: x}
	service.Inventory.Selections = store
	actor, err := current.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, refs, err := service.recordingSelectionReferences(t.Context(), actor.Principal, handles)
	if err != nil || len(refs) != 16 || len(store.reads) != 2 {
		t.Fatal("repeated perhandle reads or lost references", err, len(refs), store.reads)
	}
	for i, ref := range refs {
		if ref.SourceID != x.rows[15-i].Source.Binding.SourceID {
			t.Fatal("reference/handle association reordered", i, ref.SourceID)
		}
	}
	t.Log("16 exactsource handles require2 existing selection-set reads; no writes, sourcequeries, newbatchport or TTLrenewal")
}
