package capture

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type inventoryFixture struct {
	f             *investigationFixture
	rows          []RecordingCandidate
	policy        RecordingPolicy
	sets          map[string]value.RecordingSelectionSet
	reads, writes int
	denyWorkload  bool
	denyPod       string
	denyPods      map[string]bool
}

func (f *inventoryFixture) WorkloadPermissions(ctx context.Context, t authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	p, err := f.f.Permissions(ctx, authorization.Target{ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID})
	if f.denyWorkload {
		p.Denies = p.Allows
	}
	return authorization.WorkloadProjection{Target: t, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}, err
}
func (f *inventoryFixture) RecordingCandidates(_ context.Context, _ authorization.WorkloadTarget, query RecordingCandidateQuery) (RecordingCandidatePage, error) {
	f.reads++
	var page RecordingCandidatePage
	for _, row := range f.rows {
		if query.PolicyUID != "" && row.Source.Binding.PolicyUID != query.PolicyUID || row.Source.Binding.SourceID <= query.AfterSourceID {
			continue
		}
		if len(page.Rows) == value.MaxRecordingSelections {
			page.More = true
			break
		}
		page.Rows = append(page.Rows, row)
		page.AfterSourceID = row.Source.Binding.SourceID
	}
	return page, nil
}
func (f *inventoryFixture) RecordingSources(_ context.Context, _ authorization.WorkloadTarget, ids []string) ([]RecordingCandidate, error) {
	f.reads++
	var rows []RecordingCandidate
	for _, row := range f.rows {
		for _, id := range ids {
			if row.Source.Binding.SourceID == id {
				rows = append(rows, row)
			}
		}
	}
	return rows, nil
}
func (f *inventoryFixture) RecordingPolicy(context.Context, string, string) (RecordingPolicy, error) {
	return f.policy, nil
}
func (f *inventoryFixture) CreateRecordingSelection(_ context.Context, s value.RecordingSelectionSet) error {
	f.writes++
	f.sets[s.ID] = s.Clone()
	return nil
}
func (f *inventoryFixture) ReadRecordingSelection(_ context.Context, actor identity.Principal, id string) (value.RecordingSelectionSet, error) {
	s, ok := f.sets[id]
	if !ok || s.Actor != actor {
		return value.RecordingSelectionSet{}, value.ErrDenied
	}
	return s.Clone(), nil
}
func (f *inventoryFixture) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	i, err := current.ResolveIdentity(ctx)
	if err != nil || target.PodUID == f.denyPod || f.denyPods[target.PodUID] {
		return authorization.CaptureEligibility{}
	}
	return authorization.CaptureEligibility{Result: authorization.Result{Eligible: true, Principal: i.Principal, ValidUntil: i.ValidUntil}, Target: target, VerifiedIdentity: i}
}
func newRecordingInventoryFixture(t *testing.T, count int) (*inventoryFixture, RecordingInventory, authorization.WorkloadTarget, fixtureIdentityResolverHandle) {
	cohort := newSourceCohortFixture(t, 1)
	if err := cohort.maintain(0); err != nil {
		t.Fatal(err)
	}
	f := newInvestigationFixture()
	f.now = cohort.f.now
	var source PolicySourceState
	for _, r := range cohort.rows {
		source = r
	}
	cohort.policy.RecordingSaves = true
	accepted := &teamRecordingAuthority{f: f, authority: cohort.authority}
	p, _ := accepted.AcceptedPolicyAuthority(t.Context(), source.Binding.PolicyUID)
	x := &inventoryFixture{f: f, policy: RecordingPolicy{Policy: cohort.policy, Accepted: p}, sets: map[string]value.RecordingSelectionSet{}}
	for n := 0; n < count; n++ {
		s := source
		s.Binding.SourceID = fixtureID(600 + n)
		s.Binding.PodUID = fixtureID(700 + n)
		s.Binding.AudienceDigest = [32]byte{1}
		s.Audience = []artifact.AudienceAssignment{f.audience}
		r := f.target.Request
		r.PodUID = s.Binding.PodUID
		pin := f.target.Pin
		pin.UID = r.PodUID
		s.Target = &targets.SourceSnapshotTarget{Request: r, Pin: pin, NodeUID: s.Binding.NodeUID, BootID: s.Binding.BootID, CollectorPodUID: s.Binding.CollectorPodUID, CollectorEpoch: s.Binding.CollectorEpoch, SourceID: s.Binding.SourceID, Fence: s.Binding.Fence, BindingDigest: [32]byte{1}}
		x.rows = append(x.rows, RecordingCandidate{PolicyName: "recording", Source: s})
	}
	svc := RecordingInventory{RootID: f.svc.RootID, Permissions: x, Eligibility: x, Candidates: x, Policies: x, Selections: x, Accepted: accepted, Now: func() time.Time { return f.now }, NewID: f.svc.NewID}
	target := authorization.WorkloadTarget{ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, WorkloadUID: source.WorkloadUID}
	current := fixtureIdentityResolverHandle{f}
	return x, svc, target, current
}

func TestRecordingInventoryAuthorizesBeforeLookupAndKeepsCursorExpiry(t *testing.T) {
	x, svc, target, current := newRecordingInventoryFixture(t, 3)
	f := x.f
	x.denyWorkload = true
	if _, err := svc.List(t.Context(), current, target, "", "", 1); err == nil || x.reads != 0 || x.writes != 0 {
		t.Fatal("denied workload queried source metadata", err, x.reads)
	}
	x.denyWorkload = false
	x.denyPod = x.rows[2].Source.Binding.PodUID
	page, err := svc.List(t.Context(), current, target, "", "", 1)
	if err != nil || len(page.Rows) != 1 || page.Cursor == "" || x.writes != 1 {
		t.Fatal("first authorized passive page", page, err)
	}
	if page.Rows[0].State != "Unknown" || page.Rows[0].History != "Unknown" || page.Rows[0].Handle == "" {
		t.Fatal("SQL source times became observed coverage", page)
	}
	f.now = f.now.Add(time.Second)
	next, err := svc.List(t.Context(), current, target, "", page.Cursor, 1)
	if err != nil || len(next.Rows) != 1 || next.Rows[0].PodUID == page.Rows[0].PodUID || next.Cursor != "" || !next.ExpiresAt.Equal(page.ExpiresAt) || x.writes != 1 {
		t.Fatal("paging renewed or replaced selection", next, err)
	}
	f.actor.ClientID = "other-client"
	if _, err = svc.List(t.Context(), current, target, "", page.Cursor, 1); err == nil {
		t.Fatal("cursor crossed client")
	}
	f.actor.ClientID = "console"
	f.now = page.ExpiresAt
	if _, err = svc.List(t.Context(), current, target, "", page.Cursor, 1); err == nil {
		t.Fatal("expired cursor renewed selection")
	}
}

func TestRecordingInventoryPagesPastHundredWithoutRenewingSelection(t *testing.T) {
	x, svc, target, current := newRecordingInventoryFixture(t, 101)
	var cursor string
	var expiry time.Time
	seen := map[string]bool{}
	for pageNumber := 0; pageNumber < 6; pageNumber++ {
		page, err := svc.List(t.Context(), current, target, "", cursor, 20)
		if err != nil {
			t.Fatal("bounded inventory beyond one hundred sources", pageNumber, err)
		}
		if pageNumber == 0 {
			expiry = page.ExpiresAt
		}
		if !page.ExpiresAt.Equal(expiry) || len(page.Rows) > 20 {
			t.Fatal("page renewed or exceeded bounds", page)
		}
		for _, row := range page.Rows {
			if seen[row.PodUID] {
				t.Fatal("repeated inventory row", row.PodUID)
			}
			seen[row.PodUID] = true
		}
		cursor = page.Cursor
		if pageNumber < 5 && cursor == "" {
			t.Fatal("inventory truncated at batch boundary", pageNumber, len(seen))
		}
		x.f.now = x.f.now.Add(time.Millisecond)
	}
	if cursor != "" || len(seen) != 101 || x.writes != 2 {
		t.Fatal("keyset paging lost sources or rewrote each display page", cursor, len(seen), x.writes)
	}
}

func TestRecordingInventoryPolicyFilterPrecedesBatchLimit(t *testing.T) {
	x, svc, target, current := newRecordingInventoryFixture(t, 101)
	policy := x.rows[100].Source.Binding.PolicyUID
	for n := 0; n < 100; n++ {
		x.rows[n].Source.Binding.PolicyUID = "another-policy"
	}
	page, err := svc.List(t.Context(), current, target, policy, "", 20)
	if err != nil || len(page.Rows) != 1 || page.Rows[0].PodUID != x.rows[100].Source.Binding.PodUID || page.Cursor != "" {
		t.Fatal("policy filter was applied after scan limit", page, err)
	}
	id, _, ok := value.ParseRecordingHandle(page.Rows[0].Handle)
	if !ok {
		t.Fatal("missing opaque selection")
	}
	set := x.sets[id]
	sources, err := x.RecordingSources(t.Context(), target, []string{set.References[0].SourceID})
	if err != nil || len(sources) != 1 || sources[0].Source.Binding.SourceID != x.rows[100].Source.Binding.SourceID {
		t.Fatal("later source requires first batch scan", sources, err)
	}
}
func TestRecordingInventoryCanContinuePastWhollyDeniedBatch(t *testing.T) {
	x, svc, target, current := newRecordingInventoryFixture(t, 101)
	x.denyPods = map[string]bool{}
	for _, row := range x.rows[:100] {
		x.denyPods[row.Source.Binding.PodUID] = true
	}
	first, err := svc.List(t.Context(), current, target, "", "", 20)
	if err != nil || len(first.Rows) != 0 || first.Cursor == "" {
		t.Fatal("empty authorized scan cannot continue", first, err)
	}
	if _, _, ok := value.ParseRecordingHandle(first.Cursor); ok {
		t.Fatal("batch cursor became a selectable source handle")
	}
	if _, err = svc.List(t.Context(), current, target, "changed-policy", first.Cursor, 20); err == nil {
		t.Fatal("cursor changed policy filter")
	}
	x.f.now = x.f.now.Add(time.Millisecond)
	next, err := svc.List(t.Context(), current, target, "", first.Cursor, 20)
	if err != nil || len(next.Rows) != 1 || next.Cursor != "" || !next.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatal("denied batch lost later permitted source or renewed expiry", next, err)
	}
}
