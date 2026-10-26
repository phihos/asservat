package capture

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

const (
	activationInstallation = "22222222-2222-4222-8222-222222222222"
	activationRoot         = "33333333-3333-4333-8333-333333333333"
	activationHub          = "44444444-4444-4444-8444-444444444444"
	activationCluster      = "11111111-1111-4111-8111-111111111111"
)

// activationFixture mimics the SQL facts strictly: the automation reader and
// acceptor apply the same domain validity checks as the real transactions.
type activationFixture struct {
	now         time.Time
	author      identity.Identity
	delegation  identity.Revision
	projection  authorization.Projection
	envelope    authorization.AutomationEnvelope
	observed    []value.PolicySource
	accepted    []value.PolicyAdmission
	previous    *value.PolicyAcceptance
	status      value.PolicyStatus
	noDelegates bool
}

func newActivationFixture(t *testing.T) *activationFixture {
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &activationFixture{now: now, delegation: identity.Revision{UID: "binding-uid", Generation: 3, Digest: artifact.Digest{3}}, envelope: authorization.AutomationEnvelope{AllowedActions: []string{authorization.PolicyContextAction}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 1 << 30}}
	f.author = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "developer", ClientID: "mcp", Kind: identity.Human}, Scopes: []string{"evidence:read", "evidence:capture"}, Groups: []string{"team-a"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	owner := artifact.AudienceAssignment{Kind: "Group", Issuer: f.author.Principal.Issuer, SubjectID: "team-a", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: f.delegation.UID, BasisDigest: artifact.Digest{4}, AssignmentID: "55555555-5555-4555-8555-555555555555"}
	other := owner
	other.SubjectID, other.AssignmentID, other.BasisUID = "team-b", "66666666-6666-4666-8666-666666666666", "other-binding"
	f.projection = authorization.Projection{Revision: identity.Revision{UID: "77777777-7777-4777-8777-777777777777", Generation: 9, Digest: artifact.Digest{5}}, ObservedAt: now, FreshUntil: now.Add(20 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(20 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: owner, ObservedAt: now, FreshUntil: now.Add(20 * time.Second)}, {Audience: other, ObservedAt: now, FreshUntil: now.Add(20 * time.Second)}}}
	f.status = value.PolicyStatus{PolicyUID: "policy-uid"}
	return f
}

func (f *activationFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.author, nil
}
func (f *activationFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return artifact.RecoveryProof{InstallationID: activationInstallation, IssuerEpoch: "88888888-8888-4888-8888-888888888888", Revision: identity.Revision{UID: "recovery", Generation: 1, Digest: artifact.Digest{6}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *activationFixture) ReadPolicy(context.Context, string, string) (value.PolicySource, []byte, error) {
	spec := restartSpec()
	spec["target"].(map[string]any)["cluster"] = activationCluster
	b, _ := json.Marshal(spec)
	return value.PolicySource{InstallationID: activationInstallation, ClusterID: activationHub, NamespaceUID: "control-uid", Name: "restarts", Revision: identity.Revision{UID: "policy-uid", Generation: 1, Digest: artifact.Digest{7}}, ResourceVersion: "1", ObservedAt: f.now, FreshUntil: f.now.Add(30 * time.Second), CollectionDigest: artifact.Digest{8}}, b, nil
}
func (f *activationFixture) ObservePolicy(_ context.Context, s value.PolicySource) error {
	f.observed = append(f.observed, s)
	return nil
}
func (f *activationFixture) ObserveWorkloadRestarts(_ context.Context, r targets.RestartRequest) (targets.RestartObservation, error) {
	return targets.RestartObservation{ClusterID: r.ClusterID, Namespace: configuration.NamespaceRef{Name: r.Namespace, UID: "ns-uid"}, Workload: configuration.WorkloadRef{Kind: r.Kind, Name: r.Name, UID: "workload-uid"}, Pods: []targets.PodRestarts{}, Probe: r.Probe, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *activationFixture) Delegation(context.Context, authorization.Target) (identity.Revision, error) {
	if f.noDelegates {
		return identity.Revision{}, value.ErrDenied
	}
	return f.delegation, nil
}
func (f *activationFixture) ActiveClusterPolicies(context.Context, string, string) (int64, error) {
	return 0, nil
}
func (f *activationFixture) AcceptanceByNonce(context.Context, string) (value.PolicyAcceptance, bool, error) {
	if f.previous != nil {
		return *f.previous, true, nil
	}
	return value.PolicyAcceptance{}, false, nil
}
func (f *activationFixture) Status(context.Context, string) (value.PolicyStatus, error) {
	return f.status, nil
}
func (f *activationFixture) Permissions(_ context.Context, t authorization.Target) (authorization.Projection, error) {
	p := f.projection
	p.Target = t
	return p, nil
}

// PolicyAutomationAuthority applies the SQL reader's own preconditions.
func (f *activationFixture) PolicyAutomationAuthority(_ context.Context, a authorization.AcceptedPolicyAuthority, t authorization.Target) (authorization.AutomationProjection, error) {
	if !a.Valid(time.Now()) || a.InstallationID != activationInstallation || t.ClusterID != a.ClusterID || t.NamespaceUID != a.NamespaceUID || t.WorkloadUID != a.WorkloadUID || a.Delegation != f.delegation {
		return authorization.AutomationProjection{}, value.ErrDenied
	}
	p, _ := f.Permissions(context.Background(), t)
	return authorization.AutomationProjection{InstallationID: activationInstallation, Delegation: f.delegation, Envelope: f.envelope, ObservedAt: f.now, FreshUntil: f.now.Add(20 * time.Second), Permissions: p}, nil
}

// AcceptPolicy applies the admission transaction's domain checks.
func (f *activationFixture) AcceptPolicy(_ context.Context, in value.PolicyAdmission) (value.AcceptedPolicy, error) {
	now := time.Now()
	if !in.Valid(now) || in.RootID != activationRoot {
		return value.AcceptedPolicy{}, value.ErrInvalid
	}
	p, err := f.PolicyAutomationAuthority(context.Background(), in.Authority, in.Target)
	if err != nil {
		return value.AcceptedPolicy{}, err
	}
	use := authorization.PolicyUse{PolicyUID: in.Authority.PolicyUID, ScopeDigest: in.Authority.ScopeDigest, Target: in.Target, Purpose: authorization.PolicyIncident}
	if !authorization.ValidatePolicyAcceptance(in.Author, in.Authority, p, use, now).Eligible {
		return value.AcceptedPolicy{}, value.ErrDenied
	}
	f.accepted = append(f.accepted, in)
	return value.AcceptedPolicy{Record: value.PolicyAcceptance{ID: "99999999-9999-4999-8999-999999999999", Authority: in.Authority, Submitter: in.Author.Principal}}, nil
}
func (f *activationFixture) PublishPolicyAcceptances(context.Context) error { return nil }

func (f *activationFixture) activation() PolicyActivation {
	return PolicyActivation{RootID: activationRoot, InstallationID: activationInstallation, RecipeName: "builtin-pod-status-v1", RecipeDigest: testRecipe, Documents: f, Sources: f, Observer: f, Ledger: f, Permissions: f, Automation: f, Acceptor: f, Audit: f, Recovery: f, Now: time.Now}
}

func TestPolicyActivationAcceptsTheTeamScopeWithEnvelopeLimits(t *testing.T) {
	f := newActivationFixture(t)
	r, err := f.activation().Activate(context.Background(), f, "restarts", "key-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.accepted) != 1 || len(f.observed) != 1 || !r.Audited || r.Replay || r.MaxExecutions != 10 {
		t.Fatal("activation", r, len(f.accepted))
	}
	a := f.accepted[0].Authority
	if a.Executor != authorization.PolicyPrincipal(activationInstallation, "policy-uid") || a.Creator != f.author.Principal || a.WorkloadUID != "workload-uid" || a.NamespaceUID != "ns-uid" || a.ClusterID != activationCluster || len(a.Owners) != 1 || a.Owners[0].SubjectID != "team-a" || a.Limits.MaxObservedBytes != 0 || a.NotAfter.Sub(a.IssuedAt) != time.Hour {
		t.Fatalf("accepted authority %+v", a)
	}
	s := f.accepted[0].Submission
	if s.ClusterID != activationHub || s.NamespaceUID != "control-uid" || s.ReplacesID != "" {
		t.Fatal("submission does not name the hub-held policy object", s)
	}
	// The same key retries into the original acceptance without accepting again.
	f.previous = &value.PolicyAcceptance{ID: r.AcceptanceID, Authority: a, Submitter: f.author.Principal}
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: r.AcceptanceID, Authority: a, NotAfter: a.NotAfter, MaxExecutions: 10}
	again, err := f.activation().Activate(context.Background(), f, "restarts", "key-1")
	if err != nil || !again.Replay || again.AcceptanceID != r.AcceptanceID || len(f.accepted) != 1 {
		t.Fatal("retry was not the original acceptance", again, err)
	}
	// An already accepted, unchanged scope is never accepted again.
	f.previous = nil
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: r.AcceptanceID, Authority: a, NotAfter: a.NotAfter, MaxExecutions: 10}
	unchanged, err := f.activation().Activate(context.Background(), f, "restarts", "key-2")
	if err != nil || !unchanged.Replay || len(f.accepted) != 1 {
		t.Fatal("unchanged source accepted twice", unchanged, err)
	}
}

func TestPolicyActivationRefusesWithoutTeamDelegation(t *testing.T) {
	for _, name := range []string{"no-binding", "not-a-sponsor", "envelope-lacks-snapshot", "workload-identity", "missing-capture-scope"} {
		t.Run(name, func(t *testing.T) {
			f := newActivationFixture(t)
			want := ErrPolicyDelegation
			switch name {
			case "no-binding":
				f.noDelegates = true
			case "not-a-sponsor":
				f.author.Groups = []string{"team-b"}
			case "envelope-lacks-snapshot":
				f.envelope.AllowedActions = []string{"logs"}
			case "workload-identity":
				f.author.Principal.Kind = identity.Workload
				want = value.ErrDenied
			case "missing-capture-scope":
				f.author.Scopes = []string{"evidence:read"}
			}
			if _, err := f.activation().Activate(context.Background(), f, "restarts", "key"); !errors.Is(err, want) || len(f.accepted) != 0 {
				t.Fatal("activation not refused", err)
			}
		})
	}
}

// DeactivatePolicy applies the SQL transaction's own rules.
func (f *activationFixture) DeactivatePolicy(_ context.Context, policy, acceptance string) (bool, error) {
	switch {
	case f.status.ActiveID == acceptance:
		f.status.ActiveID, f.status.DeactivatedID = "", acceptance
		return false, nil
	case f.status.ActiveID == "" && f.status.DeactivatedID == acceptance:
		return true, nil
	}
	return false, value.ErrConflict
}

func (f *activationFixture) deactivation() PolicyDeactivation {
	return PolicyDeactivation{RootID: activationRoot, InstallationID: activationInstallation, Documents: f, Ledger: f, Permissions: f, Recovery: f, Now: time.Now}
}

func TestPolicyDeactivationIsIdempotentAndBlocksReactivationOfTheSameScope(t *testing.T) {
	f := newActivationFixture(t)
	r, err := f.activation().Activate(context.Background(), f, "restarts", "key-1")
	if err != nil {
		t.Fatal(err)
	}
	a := f.accepted[0].Authority
	f.status = value.PolicyStatus{PolicyUID: "policy-uid", ActiveID: r.AcceptanceID, Authority: a, NotAfter: a.NotAfter, MaxExecutions: 10, ExecutionsSpent: 3}
	// A maintainer of another binding cannot stop the team's policy.
	stranger := *f
	stranger.author.Groups = []string{"team-b"}
	if _, err := stranger.deactivation().Deactivate(context.Background(), &stranger, "restarts"); !errors.Is(err, ErrPolicyDelegation) || stranger.status.ActiveID == "" {
		t.Fatal("a non-sponsor deactivated the policy", err)
	}
	d, err := f.deactivation().Deactivate(context.Background(), f, "restarts")
	if err != nil || d.Replay || d.AcceptanceID != r.AcceptanceID || f.status.ActiveID != "" || f.status.ExecutionsSpent != 3 {
		t.Fatal("deactivation", d, err)
	}
	again, err := f.deactivation().Deactivate(context.Background(), f, "restarts")
	if err != nil || !again.Replay || again.AcceptanceID != r.AcceptanceID {
		t.Fatal("repeated deactivation is not a replay", again, err)
	}
	// Neither a retried activation nor a new key revives the deactivated scope.
	f.previous = &value.PolicyAcceptance{ID: r.AcceptanceID, Authority: a, Submitter: f.author.Principal}
	if _, err := f.activation().Activate(context.Background(), f, "restarts", "key-1"); !errors.Is(err, ErrPolicyDeactivated) {
		t.Fatal("retried activation reported a deactivated acceptance", err)
	}
	f.previous = nil
	if _, err := f.activation().Activate(context.Background(), f, "restarts", "key-2"); !errors.Is(err, ErrPolicyDeactivated) || len(f.accepted) != 1 {
		t.Fatal("deactivated scope accepted again", err)
	}
	// A workload identity, or a never-accepted policy, cannot be deactivated.
	f.author.Principal.Kind = identity.Workload
	if _, err := f.deactivation().Deactivate(context.Background(), f, "restarts"); !errors.Is(err, value.ErrDenied) {
		t.Fatal("workload identity deactivated", err)
	}
	g := newActivationFixture(t)
	if _, err := g.deactivation().Deactivate(context.Background(), g, "restarts"); !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("never-accepted policy deactivated", err)
	}
}
