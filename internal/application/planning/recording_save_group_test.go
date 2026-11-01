package planning

import (
	value "asservat.local/asservat/internal/domain/planning"
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
)

func TestRecordingSaveGroupCanonicalScopePreservesCompleteSelection(t *testing.T) {
	in, now := recordingSaveScopeInput(t)
	second := in.Sources[0]
	second.CeilingDigest = artifact.Digest{77}
	second.RetentionDigest = artifact.Digest{88}
	second.Original.SourceID = "00000000-0000-4000-8000-000000000075"
	second.Original.Request.PodUID = "second-pod"
	second.Original.Pin.UID = "second-pod"
	in.Sources = append(in.Sources, second)
	in.IncidentPodLimit = 2
	raw, digest, err := CompileRecordingSaveScope(in, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadContextScopeIdentity(raw, digest)
	if err != nil || got.CaptureID != in.CaptureID {
		t.Fatal("valid reviewed two-source selection cannot be read", err)
	}
	in.Sources[1].MaxBytes--
	_, other, err := CompileRecordingSaveScope(in, now)
	if err != nil || other == digest || digest == (artifact.Digest{}) {
		t.Fatal("later selected member absent from full selection digest", err)
	}
}

func groupedRecordingSavePlans(t *testing.T) ([]value.ContextPlan, []artifact.Registration, time.Time) {
	t.Helper()
	base, registration, now := manualSnapshotPlan(t)
	scope, _ := recordingSaveScopeInput(t)
	source := &scope.Sources[0]
	source.ActionID, source.Before, source.MaxBytes = base.Input.Snapshot.ActionID, base.Input.Snapshot.Request.Before, base.Input.Snapshot.Request.MaxBytes
	scope.CeilingDigest = artifact.Digest(base.Input.Capability.Revision.Digest)
	scope.RetentionDigest = artifact.Digest(base.Input.Retention.PolicyRevision.Digest)
	second := *source
	second.CeilingDigest = artifact.Digest{77}
	second.RetentionDigest = artifact.Digest{88}
	second.Original.SourceID = "00000000-0000-4000-8000-000000000075"
	second.Original.Request.PodUID = "second-pod"
	second.Original.Pin.UID = "second-pod"
	scope.Sources = append(scope.Sources, second)
	scope.IncidentPodLimit = 2
	raw, digest, err := CompileRecordingSaveScope(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	plans := make([]value.ContextPlan, 2)
	registrations := make([]artifact.Registration, 2)
	for index, source := range scope.Sources {
		in := base.Input
		in.CaptureID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 801+index)
		in.Snapshot = base.Input.Snapshot.Clone()
		in.Snapshot.Group = &value.RecordingSaveGroupBinding{ParentCaptureID: scope.CaptureID, SelectionDigest: digest, ChildIndex: index, ChildCount: 2}
		in.Snapshot.RecordingSaveScope = raw
		original := source.Original
		in.Snapshot.SourceTarget = &original
		in.Snapshot.Request.SourceID = source.Original.SourceID
		in.Snapshot.Request.SnapshotID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 811+index)
		in.Target.Request = original.Request
		in.Target.Pin = original.Pin
		in.Retention.Target = in.Target.Target()
		if source.CeilingDigest != (artifact.Digest{}) {
			in.Capability.Revision.Digest = [32]byte(source.CeilingDigest)
		}
		if source.RetentionDigest != (artifact.Digest{}) {
			in.Retention.PolicyRevision.Digest = [32]byte(source.RetentionDigest)
		}
		plans[index], err = CompileContext(in, now)
		if err != nil {
			t.Fatalf("child %d cannot retain full reviewed selection: %v", index, err)
		}
		registrations[index] = registration
		registrations[index].Location.ArtifactID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 821+index)
		registrations[index].Location.AttemptID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 831+index)
	}
	return plans, registrations, now
}

func TestRecordingSaveGroupChildrenBindWholeScopeAndCommonAcceptanceT0(t *testing.T) {
	plans, registrations, now := groupedRecordingSavePlans(t)
	if plans[0].ScopeDigest != plans[1].ScopeDigest || !bytes.Equal(plans[0].CanonicalScope, plans[1].CanonicalScope) || plans[0].Input.CaptureID == plans[1].Input.CaptureID || registrations[0].Location.AttemptID == registrations[1].Location.AttemptID {
		t.Fatal("child custody identities or reviewed parent scope collapsed")
	}
	parent, err := ReadContextScopeIdentity(plans[0].CanonicalScope, plans[0].ScopeDigest)
	if err != nil || parent.Target.PodUID != "" || len(parent.Targets) != 2 || parent.CaptureID == plans[0].Input.CaptureID {
		t.Fatal("parent impersonated one child", err)
	}
	t0 := now.Add(2300 * time.Millisecond)
	for index, plan := range plans {
		child, err := ReadRecordingSaveChildScopeIdentity(plan.CanonicalScope, plan.ScopeDigest, *plan.Input.Snapshot.Group, plan.Input.CaptureID)
		if err != nil || child.CaptureID != plan.Input.CaptureID || child.Target != plan.Input.Target.Target() || len(child.Targets) != 0 {
			t.Fatal("wrong child identity", err)
		}
		accepted, r, err := ReanchorRecordingSave(plan, registrations[index], t0, now.Add(time.Hour))
		if err != nil || !accepted.Input.Snapshot.Request.T0.Equal(t0) || !r.AnchorAt.Equal(t0.Add(-plan.Input.Snapshot.Request.Before)) || accepted.Input.Snapshot.Group.SelectionDigest != plan.ScopeDigest {
			t.Fatal("child acceptance changed common time or selection", err)
		}
	}
}

func TestRecordingSaveGroupRejectsMismatchedChildMembership(t *testing.T) {
	for name, change := range map[string]func(*value.ContextInput){
		"parent":              func(in *value.ContextInput) { in.Snapshot.Group.ParentCaptureID = in.CaptureID },
		"selection":           func(in *value.ContextInput) { in.Snapshot.Group.SelectionDigest[0]++ },
		"index":               func(in *value.ContextInput) { in.Snapshot.Group.ChildIndex = 1 },
		"negative index":      func(in *value.ContextInput) { in.Snapshot.Group.ChildIndex = -1 },
		"count":               func(in *value.ContextInput) { in.Snapshot.Group.ChildCount = 1 },
		"missing binding":     func(in *value.ContextInput) { in.Snapshot.Group = nil },
		"policy trigger":      func(in *value.ContextInput) { in.Snapshot.TriggerKind = "policy"; in.Snapshot.RecordingSaveScope = nil },
		"window":              func(in *value.ContextInput) { in.Snapshot.Request.MaxBytes-- },
		"other Pod retention": func(in *value.ContextInput) { in.Retention.PolicyRevision.Digest[0]++ },
		"other Pod ceiling":   func(in *value.ContextInput) { in.Capability.Revision.Digest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			plans, _, now := groupedRecordingSavePlans(t)
			in := plans[0].Input
			in.Snapshot = in.Snapshot.Clone()
			change(&in)
			if _, err := CompileContext(in, now); err == nil {
				t.Fatal("mismatched group child accepted")
			}
		})
	}
}

func TestRecordingSaveGroupOptionalBindingPreservesLegacySerializationAndClone(t *testing.T) {
	plan, _, _ := manualSnapshotPlan(t)
	before, err := json.Marshal(plan.Input.Snapshot)
	if err != nil || bytes.Contains(before, []byte(`"Group":`)) {
		t.Fatal("legacy snapshot gained group metadata", err)
	}
	clone := plan.Input.Snapshot.Clone()
	after, _ := json.Marshal(clone)
	if !bytes.Equal(before, after) {
		t.Fatal("legacy clone changed persisted bytes")
	}
	plans, _, _ := groupedRecordingSavePlans(t)
	clone = plans[0].Input.Snapshot.Clone()
	clone.Group.ChildIndex = 1
	if plans[0].Input.Snapshot.Group.ChildIndex != 0 {
		t.Fatal("caller can mutate protected group membership")
	}
}

func TestRecordingSaveGroupChecksLaterMemberCanonicalGuards(t *testing.T) {
	plans, _, _ := groupedRecordingSavePlans(t)
	for name, change := range map[string]func(*recordingSaveScope){
		"invalid later member":  func(s *recordingSaveScope) { s.Sources[1].BootID = "" },
		"reordered":             func(s *recordingSaveScope) { s.Sources[0], s.Sources[1] = s.Sources[1], s.Sources[0] },
		"duplicate":             func(s *recordingSaveScope) { s.Sources[1] = s.Sources[0] },
		"wrong aggregate proof": func(s *recordingSaveScope) { s.Sources[1].RetentionDigest = s.Sources[0].RetentionDigest },
	} {
		t.Run(name, func(t *testing.T) {
			var scope recordingSaveScope
			if json.Unmarshal(plans[0].CanonicalScope, &scope) != nil {
				t.Fatal("fixture")
			}
			change(&scope)
			encoded, _ := json.Marshal(scope)
			raw, digest, err := canonical(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadContextScopeIdentity(raw, digest); err == nil {
				t.Fatal("invalid later member accepted")
			}
		})
	}
}

func TestRecordingSaveGroupIncidentCapCountsDistinctPodsAndBoundsSixteenSources(t *testing.T) {
	in, now := recordingSaveScopeInput(t)
	second := in.Sources[0]
	second.Original.SourceID = "00000000-0000-4000-8000-000000000075"
	second.ActionID = "second-action"
	in.Sources = append(in.Sources, second)
	raw, digest, err := CompileRecordingSaveScope(in, now)
	if err != nil {
		t.Fatal("two action sources on one Pod exceed incident Pod cap", err)
	}
	if _, err := ReadContextScopeIdentity(raw, digest); err != nil {
		t.Fatal(err)
	}
	in.IncidentPodLimit = 16
	for index := 2; index < 16; index++ {
		source := in.Sources[0]
		source.Original.SourceID = fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+index)
		source.Original.Request.PodUID = fmt.Sprintf("pod-%d", index)
		source.Original.Pin.UID = source.Original.Request.PodUID
		in.Sources = append(in.Sources, source)
	}
	raw, digest, err = CompileRecordingSaveScope(in, now)
	if err != nil || len(raw) > 65536 {
		t.Fatal("sixteen-member scope exceeds existing bound", len(raw), err)
	}
	if got, err := ReadContextScopeIdentity(raw, digest); err != nil || len(got.Targets) != 16 {
		t.Fatal("sixteen-member selection unreadable", err)
	}
	extra := in.Sources[0]
	extra.Original.SourceID = "00000000-0000-4000-8000-000000000999"
	extra.ActionID = "third-action"
	in.Sources = append(in.Sources, extra)
	if _, _, err := CompileRecordingSaveScope(in, now); err == nil {
		t.Fatal("seventeen source selection accepted")
	}
	t.Logf("configured sixteen-source scope JSON: %d bytes (existing max65536)", len(raw))
}

func TestRecordingSaveChildIdentityDoesNotAcceptAutomaticScope(t *testing.T) {
	in, now := sourceSnapshotInput(t)
	plan, err := CompileContext(in, now)
	if err != nil {
		t.Fatal(err)
	}
	group := value.RecordingSaveGroupBinding{ParentCaptureID: in.CaptureID, SelectionDigest: plan.ScopeDigest, ChildCount: 1}
	if _, err := ReadRecordingSaveChildScopeIdentity(plan.CanonicalScope, plan.ScopeDigest, group, "00000000-0000-4000-8000-000000000801"); err == nil {
		t.Fatal("automatic scope became group membership")
	}
}

func TestRecordingSaveGroupAcceptanceKeepsOriginalIngressEnd(t *testing.T) {
	plans, registrations, now := groupedRecordingSavePlans(t)
	parent, err := ReadContextScopeIdentity(plans[0].CanonicalScope, plans[0].ScopeDigest)
	if err != nil || parent.Requester == nil {
		t.Fatal(err)
	}
	t0 := now.Add(3 * time.Second)
	bounds := capture.GroupRequestBounds{StartedAt: now, Until: now.Add(15 * time.Second), Requester: *parent.Requester}
	for n, plan := range plans {
		accepted, _, err := ReanchorRecordingSaveGroup(plan, registrations[n], t0, now.Add(time.Hour), bounds)
		if err != nil || !accepted.Input.Snapshot.Request.StartBy.Equal(bounds.Until) {
			t.Fatal("group restarted15s after acceptance instead of original ingress", err)
		}
		if !accepted.Input.Snapshot.Request.T0.Equal(t0) || accepted.ScopeDigest != plan.ScopeDigest || !plan.Input.Snapshot.Request.StartBy.Equal(now.Add(5*time.Second)) {
			t.Fatal("group acceptance changed original plan identity")
		}
		short := bounds
		short.Until = now.Add(4 * time.Second)
		accepted, _, err = ReanchorRecordingSaveGroup(plan, registrations[n], t0, now.Add(time.Hour), short)
		if err != nil || !accepted.Input.Snapshot.Request.StartBy.Equal(short.Until) {
			t.Fatal("short original caller was widened", err)
		}
		legacy, _, err := ReanchorRecordingSave(plan, registrations[n], t0, now.Add(time.Hour))
		if err != nil || !legacy.Input.Snapshot.Request.StartBy.Equal(t0.Add(5*time.Second)) {
			t.Fatal("legacy group changed interval", err)
		}
	}
	for name, change := range map[string]func(*value.ContextPlan, *capture.GroupRequestBounds){
		"singleton":       func(p *value.ContextPlan, _ *capture.GroupRequestBounds) { p.Input.Snapshot.Group = nil },
		"requester":       func(_ *value.ContextPlan, b *capture.GroupRequestBounds) { b.Requester.Subject += "other" },
		"expired-ingress": func(_ *value.ContextPlan, b *capture.GroupRequestBounds) { b.Until = t0 },
		"child-index":     func(p *value.ContextPlan, _ *capture.GroupRequestBounds) { p.Input.Snapshot.Group.ChildIndex = 1 },
		"scope": func(p *value.ContextPlan, _ *capture.GroupRequestBounds) {
			p.CanonicalScope = append(append([]byte(nil), p.CanonicalScope...), byte('x'))
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := plans[0]
			p.Input.Snapshot = p.Input.Snapshot.Clone()
			b := bounds
			change(&p, &b)
			if _, _, err := ReanchorRecordingSaveGroup(p, registrations[0], t0, now.Add(time.Hour), b); err == nil {
				t.Fatal("unreviewed group bounds accepted")
			}
		})
	}
}

func TestAcceptedGroupRecompilationPreservesEveryStoredStartBound(t *testing.T) {
	plans, registrations, now := groupedRecordingSavePlans(t)
	t0 := now.Add(2 * time.Second)
	for _, span := range []time.Duration{3 * time.Second, 5 * time.Second, 15 * time.Second} {
		t.Run(span.String(), func(t *testing.T) {
			accepted, _, err := ReanchorRecordingSave(plans[0], registrations[0], t0, now.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			// The independently accepted SQL expectation supplies this exact date;
			// recompilation must never select a different interval from current time.
			accepted.Input.Snapshot.Request.StartBy = t0.Add(span)
			encoded, _ := json.Marshal(accepted.Input.Snapshot.Request)
			rebuilt, err := CompileContext(accepted.Input, t0.Add(100*time.Millisecond))
			if err != nil {
				t.Fatal("stored accepted request refused", err)
			}
			got, _ := json.Marshal(rebuilt.Input.Snapshot.Request)
			if !bytes.Equal(encoded, got) || rebuilt.ScopeDigest != accepted.ScopeDigest {
				t.Fatal("recompilation renewed or rewrote stored dates")
			}
		})
	}
}
