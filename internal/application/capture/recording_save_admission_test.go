package capture

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

type manualSaveCaller struct {
	f      *investigationFixture
	actor  identity.Principal
	denied bool
}

func (c *manualSaveCaller) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if c.denied || ctx.Err() != nil {
		return identity.Identity{}, value.ErrDenied
	}
	return identity.Identity{Principal: c.actor, Policy: identity.Revision{UID: "caller", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:capture", "evidence:read"}, Groups: []string{"current-team"}, VerifiedAt: c.f.now, ValidUntil: c.f.now.Add(5 * time.Second)}, nil
}

func TestManualSnapshotKeepsInitiatorAndPolicyExecutorSeparate(t *testing.T) {
	cohort := newSourceCohortFixture(t, 1)
	if err := cohort.maintain(0); err != nil {
		t.Fatal(err)
	}
	f := cohort.f
	accepted := &teamRecordingAuthority{f: f, authority: cohort.authority}
	f.svc.Eligibility = authapp.CaptureEligibility{Human: authapp.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Accepted: accepted, Current: accepted, Now: func() time.Time { return f.now }}
	var source PolicySourceState
	for _, r := range cohort.rows {
		source = r
	}
	policyCurrent := newPolicyIdentity(t.Context(), accepted, cohort.authority, f.now.Add(45*time.Second), func() time.Time { return f.now })
	eligible := f.svc.Eligibility.ContextEligibilityCurrent(t.Context(), policyCurrent, f.target.Target())
	if !eligible.Eligible {
		t.Fatal("independent policy authority baseline")
	}
	source.Audience = slices.Clone(eligible.DefaultAudience)
	digest, err := compiler.SourceAudienceDigest(source.Audience)
	if err != nil {
		t.Fatal(err)
	}
	source.Binding.AudienceDigest = [32]byte(digest)
	target := f.target.Request
	target.PodUID = source.Binding.PodUID
	f.target.Request, f.target.Pin.UID = target, target.PodUID
	source.StartedAt = f.now.Add(-time.Minute)
	source.Target = &targets.SourceSnapshotTarget{Request: target, Pin: f.target.Pin, NodeUID: source.Binding.NodeUID, BootID: source.Binding.BootID, CollectorPodUID: source.Binding.CollectorPodUID, CollectorEpoch: source.Binding.CollectorEpoch, SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, BindingDigest: deliveryapp.SourceBindingDigest(source.Binding)}
	retained := &retainedSourceTargetsFixture{ContextTargets: f, now: func() time.Time { return f.now }}
	f.svc.Targets = retained
	caller := &manualSaveCaller{f: f, actor: identity.Principal{Issuer: f.audience.Issuer, Subject: "current-initiator", ClientID: "console", Kind: identity.Human}}
	cohort.policy.RecordingSaves = true
	p, _ := accepted.AcceptedPolicyAuthority(t.Context(), cohort.authority.PolicyUID)
	f.svc.PolicyAccepted = accepted
	f.svc.RecordingPolicies = &inventoryFixture{policy: RecordingPolicy{Policy: cohort.policy, Accepted: p}}
	preview, err := f.svc.previewSourceSnapshot(t.Context(), policyCurrent, PolicySnapshotSelection{PolicyName: "recording", Policy: cohort.policy, Authority: cohort.authority, Source: source, Target: target, TriggeredAt: f.now}, &manualSnapshotSelection{Current: caller, Before: 20 * time.Second})
	if err != nil {
		t.Fatal("manual source snapshot preview", err)
	}
	if preview.Preview.Actor != caller.actor || preview.Preview.Executor() != cohort.authority.Executor || preview.RecordingSave == nil || preview.RecordingSave.Before != 20*time.Second || preview.Preview.Intent.Composition != nil {
		t.Fatal("manual creator became executor or broader recipe", preview)
	}
	identity, e := compiler.ReadContextScopeIdentity(preview.Preview.CanonicalScope, preview.Preview.ScopeDigest)
	if e != nil || identity.Requester == nil || *identity.Requester != caller.actor || identity.Actor != cohort.authority.Executor {
		t.Fatal("immutable manual dual-principal scope", e)
	}
	previewT0 := preview.Preview.Intent.Snapshot.Request.T0
	f.now = f.now.Add(500 * time.Millisecond)
	admission := &retainedRecording{investigationFixture: f}
	f.svc.Admission = admission
	_, err = f.svc.Request(t.Context(), caller, preview.Preview.ID, "manual-request-key")
	if !errors.Is(err, value.ErrUnavailable) || len(admission.seen) != 0 {
		t.Fatal("passive manual preview bypassed unqualified acquisition gate", err)
	}
	f.svc.RecordingSaveEnabled = true
	_, err = f.svc.Request(t.Context(), caller, preview.Preview.ID, "manual-request-key")
	if !errors.Is(err, reachedRecordingAdmission) || len(admission.seen) != 1 {
		t.Fatal("manual request did not reach genuine shared admission boundary", err)
	}
	a := admission.seen[0]
	if a.RecordingSave == nil || a.Requester() != caller.actor || a.Plan.Input.Executor != cohort.authority.Executor || a.RecordingSave.Initiator.VerifiedIdentity.Principal != caller.actor || !a.Plan.Input.Snapshot.Request.T0.After(previewT0) || a.Plan.Input.Snapshot.Request.After != 0 {
		t.Fatal("manual request reused preview clock or lost caller/executor", a)
	}
	if retained.podReads != 0 {
		t.Fatal("manual save selected a live replacement Pod")
	}
	caller.denied = true
	if _, err = f.svc.Request(t.Context(), caller, preview.Preview.ID, "manual-request-key"); err == nil {
		t.Fatal("revoked initiator retained policy authority")
	}
}
