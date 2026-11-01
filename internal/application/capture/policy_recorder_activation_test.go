package capture

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type workloadActivationFixture struct{ *activationFixture }

func (f *workloadActivationFixture) WorkloadDelegation(_ context.Context, t authorization.WorkloadTarget) (identity.Revision, error) {
	if !t.Valid() || f.noDelegates {
		return identity.Revision{}, value.ErrDenied
	}
	return f.delegation, nil
}
func (f *workloadActivationFixture) WorkloadPermissions(_ context.Context, t authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	p := f.projection
	return authorization.WorkloadProjection{Target: t, Revision: p.Revision, ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil, DeniesComplete: p.DeniesComplete, DeniesObservedAt: p.DeniesObservedAt, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows, Denies: p.Denies}, nil
}
func (f *workloadActivationFixture) PolicyWorkloadAutomation(ctx context.Context, t authorization.WorkloadTarget, d identity.Revision) (authorization.WorkloadAutomationProjection, error) {
	if !t.Valid() || d != f.delegation {
		return authorization.WorkloadAutomationProjection{}, value.ErrDenied
	}
	p, _ := f.WorkloadPermissions(ctx, t)
	return authorization.WorkloadAutomationProjection{InstallationID: activationInstallation, Delegation: d, Envelope: f.envelope, ObservedAt: f.projection.ObservedAt, FreshUntil: f.projection.FreshUntil, Permissions: p}, nil
}
func (f *workloadActivationFixture) Delegation(context.Context, authorization.Target) (identity.Revision, error) {
	panic("recorder activation invented a concrete Pod")
}
func (f *workloadActivationFixture) Permissions(context.Context, authorization.Target) (authorization.Projection, error) {
	panic("recorder activation read concrete Pod rights")
}
func (f *workloadActivationFixture) PolicyAutomationAuthority(context.Context, authorization.AcceptedPolicyAuthority, authorization.Target) (authorization.AutomationProjection, error) {
	panic("recorder activation invented draft execution authority")
}
func (f *workloadActivationFixture) AcceptPolicy(ctx context.Context, in value.PolicyAdmission) (value.AcceptedPolicy, error) {
	if !in.Valid(f.now) || in.Workload == nil || in.Target != (authorization.Target{}) {
		return value.AcceptedPolicy{}, value.ErrInvalid
	}
	p, err := f.PolicyWorkloadAutomation(ctx, *in.Workload, in.Authority.Delegation)
	if err != nil || !authorization.ValidatePolicyWorkloadAcceptance(in.Author, in.Authority, p, f.now).Eligible {
		return value.AcceptedPolicy{}, value.ErrDenied
	}
	f.accepted = append(f.accepted, in)
	return value.AcceptedPolicy{Record: value.PolicyAcceptance{ID: "99999999-9999-4999-8999-999999999999", Authority: in.Authority, Submitter: in.Author.Principal, Sharing: in.Sharing}}, nil
}
func newWorkloadActivationFixture(t *testing.T) (*workloadActivationFixture, PolicyActivation) {
	f := &workloadActivationFixture{newActivationFixture(t)}
	f.envelope.AllowedActions = []string{"packetCapture"}
	f.status.IntentVersion = 1
	f.edit = func(s map[string]any) {
		for k := range s {
			delete(s, k)
		}
		for k, v := range recorderPolicySpec() {
			s[k] = v
		}
		s["target"].(map[string]any)["cluster"] = activationCluster
	}
	s := f.activation()
	s.Ledger, s.Permissions, s.Automation, s.Acceptor = f, f, f, f
	s.WorkloadAutomation = f
	s.CompileRecorder = testPolicyRecorderCompiler
	s.Now = func() time.Time { return f.now }
	return f, s
}
func TestRecorderPolicyActivationUsesTypedWorkloadWithoutDraftAuthority(t *testing.T) {
	f, s := newWorkloadActivationFixture(t)
	out, err := s.Activate(context.Background(), f, "restarts", "first", true)
	if err != nil || len(f.accepted) != 1 || !out.Audited {
		t.Fatal(out, err)
	}
	a := f.accepted[0]
	if a.Target != (authorization.Target{}) || a.Workload == nil || a.Workload.WorkloadUID != "workload-uid" || a.Authority.Executor != authorization.PolicyPrincipal(activationInstallation, "policy-uid") || len(a.Authority.Actions) != 1 || a.Authority.Actions[0] != "packetCapture" || a.Authority.Limits.MaxExecutions != f.envelope.MaxExecutions || a.Authority.Limits.MaxBytes != f.envelope.MaxBytes {
		t.Fatal("typed scope or envelope lost", a)
	}
	original := a.Authority
	f.status.ActiveID, f.status.Authority, f.status.NotAfter, f.status.MaxExecutions = out.AcceptanceID, original, original.NotAfter, original.Limits.MaxExecutions
	f.now = f.now.Add(time.Second)
	edit := f.edit
	f.edit = func(spec map[string]any) { edit(spec); spec["grantRef"] = "00000000-0000-4000-8000-000000000001" }
	replay, err := s.Activate(context.Background(), f, "restarts", "new-control-key", true)
	if err != nil || !replay.Replay || replay.NotAfter != original.NotAfter || len(f.accepted) != 1 {
		t.Fatal("control edit reissued scope/expiry", replay, err)
	}
	f.status.ActiveID, f.status.DeactivatedID = "", out.AcceptanceID
	if _, err := s.Activate(context.Background(), f, "restarts", "revive", true); !errors.Is(err, ErrPolicyDeactivated) {
		t.Fatal("unchanged deactivated scope revived", err)
	}
	f.status.IntentVersion++ // observed collection change/revert is a new intent
	if _, err := s.Activate(context.Background(), f, "restarts", "fresh-intent", true); err != nil || len(f.accepted) != 2 || f.accepted[1].Authority.ScopeDigest == original.ScopeDigest {
		t.Fatal("fresh intent not distinguished", err)
	}
}
func TestRecorderPolicyActivationPreservesCurrentDelegationAndDeniedWorkload(t *testing.T) {
	for _, name := range []string{"no-envelope", "no-binding", "not-sponsor", "missing-action", "explicit-deny", "pod-review", "missing-intent", "stale-workload-rights"} {
		t.Run(name, func(t *testing.T) {
			f, s := newWorkloadActivationFixture(t)
			switch name {
			case "no-envelope":
				s.WorkloadAutomation = nil
			case "no-binding":
				f.noDelegates = true
			case "not-sponsor":
				f.author.Groups = []string{"team-b"}
			case "missing-action":
				f.envelope.AllowedActions = []string{"logs"}
			case "explicit-deny":
				f.projection.Denies = append([]authorization.CurrentAssignment(nil), f.projection.Allows...)
			case "pod-review":
				f.projection.Allows[0].Reviewed = true
			case "missing-intent":
				f.status.IntentVersion = 0
			case "stale-workload-rights":
				f.projection.FreshUntil = f.now
			}
			if _, err := s.Activate(context.Background(), f, "restarts", "first", true); err == nil || len(f.accepted) != 0 {
				t.Fatal("unavailable current authority accepted", err)
			}
		})
	}
}

func TestRecorderPolicySharingControlDoesNotReissueCollectionOrResetSpend(t *testing.T) {
	f, s := newWorkloadActivationFixture(t)
	collectionEdit := f.edit
	f.withPolicySharing(f.now.Add(time.Hour))
	sharingEdit := f.edit
	f.edit = func(spec map[string]any) { collectionEdit(spec); sharingEdit(spec) }
	out, err := s.Activate(t.Context(), f, "restarts", "first", true)
	if err != nil || len(f.accepted) != 1 || f.accepted[0].Sharing == nil {
		t.Fatal("initial shared recorder", out, err)
	}
	first := f.accepted[0]
	f.status.ActiveID, f.status.Authority, f.status.NotAfter, f.status.MaxExecutions = out.AcceptanceID, first.Authority, first.Authority.NotAfter, first.Authority.Limits.MaxExecutions
	f.status.ExecutionsSpent = 3
	f.status.Sharing = &value.PolicySharingStatus{Instruction: *first.Sharing, Spent: 2}
	originalEdit := f.edit
	f.edit = func(spec map[string]any) {
		originalEdit(spec)
		sharing := spec["sharing"].(map[string]any)
		sharing["notAfter"] = f.now.Add(2 * time.Hour).UTC().Format(time.RFC3339)
		sharing["futureCaptures"].(map[string]any)["maxCaptures"] = 9
		sharing["recipients"] = []any{map[string]any{"kind": "Group", "issuer": f.author.Principal.Issuer, "id": "new-team"}}
	}
	f.now = f.now.Add(time.Second)
	replay, err := s.Activate(t.Context(), f, "restarts", "sharing-control", true)
	if err != nil || !replay.Replay || len(f.accepted) != 1 || replay.AcceptanceID != out.AcceptanceID || !replay.NotAfter.Equal(first.Authority.NotAfter) || !reflect.DeepEqual(f.status.Authority, first.Authority) {
		t.Fatal("sharing edit reissued collection authority/spend pool", replay, len(f.accepted), err)
	}
	// The admission-port count above is the observable no-reissue guarantee.
	// Retained counters are modeled; this is not SQL spend qualification.
	if f.status.ExecutionsSpent != 3 || f.status.Sharing.Spent != 2 {
		t.Fatal("retained spend changed")
	}
	if replay.Sharing == nil || replay.Sharing.NotAfter != first.Sharing.NotAfter || replay.Sharing.MaxCaptures != first.Sharing.MaxCaptures {
		t.Fatal("activation silently applied an unaccepted sharing control")
	}
}
