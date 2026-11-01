package capture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type groupPreviewFixture struct {
	*investigationFixture
	groups  int
	batches int
	seen    []value.RecordingSaveGroupAdmission
}

func (f *groupPreviewFixture) CreateRecordingGroupPreview(ctx context.Context, p value.ContextPreview) error {
	f.groups++
	return f.CreateContextPreview(ctx, p)
}
func (f *groupPreviewFixture) ReadRecordingGroupPreview(ctx context.Context, root, id string, actor identity.Principal) (value.ContextPreview, error) {
	return f.ReadContextPreview(ctx, root, id, actor)
}
func (f *groupPreviewFixture) ResolveSourceSnapshots(ctx context.Context, original []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error) {
	f.batches++
	resolver := retainedSourceTargetsFixture{ContextTargets: f.investigationFixture, now: func() time.Time { return f.now }}
	out := make([]targets.SourceSnapshotResolution, len(original))
	for n, o := range original {
		out[n], _ = resolver.ResolveSourceSnapshot(ctx, o)
	}
	return out, nil
}
func (f *groupPreviewFixture) AdmitRecordingSaveGroup(_ context.Context, a value.RecordingSaveGroupAdmission) (value.Accepted, error) {
	f.seen = append(f.seen, a)
	return value.Accepted{}, reachedRecordingAdmission
}

type groupCountingEligibility struct {
	base  ContextEligibilityReader
	calls int
}

func (e *groupCountingEligibility) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, t authorization.Target) authorization.CaptureEligibility {
	e.calls++
	return e.base.ContextEligibilityCurrent(ctx, current, t)
}

type groupSelectiveEligibility struct {
	base      ContextEligibilityReader
	deniedPod string
}

func (e groupSelectiveEligibility) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, t authorization.Target) authorization.CaptureEligibility {
	if t.PodUID == e.deniedPod {
		return authorization.CaptureEligibility{}
	}
	return e.base.ContextEligibilityCurrent(ctx, current, t)
}

func TestRecordingSaveGroupUsesOneReviewAndOneAdmission(t *testing.T) {
	for _, count := range []int{2, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			x, inv, target, _ := newRecordingInventoryFixture(t, count)
			f := x.f
			current := &manualSaveCaller{f: f, actor: f.actor}
			team, _, settings, _ := newTeamRecordingFixture(t)
			f.audience = team.audience
			f.cap.ExecutionClass = artifact.ContextAPIExecution
			f.svc.Approvals = settings
			accepted := inv.Accepted
			f.svc.Eligibility = authapp.CaptureEligibility{Human: authapp.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Accepted: accepted, Current: accepted.(*teamRecordingAuthority), Now: func() time.Time { return f.now }}
			x.policy.Policy.IncidentPods = count
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
			counting := &groupCountingEligibility{base: f.svc.Eligibility}
			f.svc.Eligibility = counting
			service := RecordingSaves{Inventory: inv, Investigation: f.svc}
			page, err := inv.List(t.Context(), current, target, "", "", 100)
			if err != nil || len(page.Rows) != count {
				t.Fatal("inventory", err, len(page.Rows))
			}
			handles := make([]string, count)
			for n, row := range page.Rows {
				handles[n] = row.Handle
			}
			slices.Reverse(handles)
			preview, err := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles, Before: time.Second})
			if err != nil {
				var failure interface{ FixedStep() string }
				if errors.As(err, &failure) {
					t.Log(failure.FixedStep())
				}
				t.Fatal("group preview", err)
			}
			if counting.calls > 4*count {
				t.Fatal("group repeats per-child checks before the final cohort check", count, counting.calls)
			}
			t.Logf("sources=%d preview_eligibility_calls=%d", count, counting.calls)
			if preview.Preview.Group == nil || fixture.groups != 1 || len(f.previews) != 1 || fixture.batches != 1 || len(preview.RecordingSave.Assessments) != count || preview.Assessment.OutputLimit != int64(count)*preview.RecordingSave.Assessments[0].Assessment.OutputLimit {
				t.Fatal("independent reviews or first-child aggregate", fixture.groups, fixture.batches)
			}
			// A stale source reference refuses the entire cohort before another journal.
			denied := service
			denied.Investigation.Eligibility = groupSelectiveEligibility{base: f.svc.Eligibility, deniedPod: x.rows[len(x.rows)-1].Source.Binding.PodUID}
			if _, e := denied.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles}); e == nil || fixture.groups != 1 {
				t.Fatal("denied selected source silently dropped or journaled", e)
			}
			originalFence := x.rows[0].Source.Binding.Fence
			x.rows[0].Source.Binding.Fence = fixtureID(9999)
			if _, e := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles}); e == nil || fixture.groups != 1 {
				t.Fatal("changed member silently dropped or journaled", e)
			}
			x.rows[0].Source.Binding.Fence = originalFence
			f.svc.RecordingSaveEnabled = false
			if _, e := f.svc.Request(t.Context(), current, preview.Preview.ID, "group-key"); !errors.Is(e, value.ErrUnavailable) || len(fixture.seen) != 0 {
				t.Fatal("passive group bypassed trusted acquisition gate", e)
			}
			f.svc.RecordingSaveEnabled = true
			baseEligibility := f.svc.Eligibility
			f.svc.Eligibility = groupSelectiveEligibility{base: baseEligibility, deniedPod: x.rows[len(x.rows)-1].Source.Binding.PodUID}
			if _, e := f.svc.Request(t.Context(), current, preview.Preview.ID, "group-key"); e == nil || len(fixture.seen) != 0 {
				t.Fatal("denied group member admitted a partial cohort", e)
			}
			f.svc.Eligibility = baseEligibility
			counting.calls = 0
			f.now = f.now.Add(100 * time.Millisecond)
			_, err = f.svc.Request(t.Context(), current, preview.Preview.ID, "group-key")
			if !errors.Is(err, reachedRecordingAdmission) || len(fixture.seen) != 1 || len(fixture.seen[0].Children) != count || fixture.batches != 4 {
				t.Fatal("not one grouped admission", err, len(fixture.seen), fixture.batches)
			}
			if counting.calls > 4*count {
				t.Fatal("group request repeats already retained original checks", count, counting.calls)
			}
			t.Logf("sources=%d request_eligibility_calls=%d", count, counting.calls)
			for n, child := range fixture.seen[0].Children {
				if !ReviewedRecordingSaveGroupChild(preview.Preview, child) || child.Plan.Input.Snapshot.Group.ChildIndex != n || !child.Plan.Input.Snapshot.Request.T0.After(preview.Preview.CreatedAt) {
					t.Fatal("lost exact reviewed member/acceptance preparation", n)
				}
			}
			changed := fixture.seen[0].Children[0]
			changed.Plan.Input.Snapshot = changed.Plan.Input.Snapshot.Clone()
			changed.Plan.Input.Snapshot.Request.Before += time.Millisecond
			if ReviewedRecordingSaveGroupChild(preview.Preview, changed) {
				t.Fatal("changed reviewed child window accepted")
			}
			if len(f.previews) != 1 {
				t.Fatal("request created child journals")
			}
		})
	}
}
