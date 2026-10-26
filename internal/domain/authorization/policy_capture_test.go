package authorization

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func policyCaptureFixture() (identity.Identity, AcceptedPolicyAuthority, AutomationProjection, Target, time.Time) {
	a, p, use, now := automationFixture()
	a.Actions = []string{PolicyContextAction}
	p.Envelope.AllowedActions = []string{PolicyContextAction, "packetCapture"}
	// A second, reader-only audience row: the default audience includes every
	// current reader, never the executor or the creator for creating it.
	reader := p.Permissions.Allows[0]
	reader.Audience.SubjectID, reader.Audience.Role, reader.Audience.AssignmentID = "readers", "evidence-reader", "33333333-3333-3333-3333-333333333334"
	p.Permissions.Allows = append(p.Permissions.Allows, reader)
	return PolicyExecutorIdentity(a, now, now.Add(20*time.Second)), a, p, use.Target, now
}

func TestPolicyExecutorCaptureEligibilityUsesTeamAuthority(t *testing.T) {
	i, a, p, target, now := policyCaptureFixture()
	e := PolicyContextEligibility(i, a, p, target, now)
	if !e.Eligible || e.Principal != a.Executor || e.VerifiedIdentity.Principal != a.Executor || e.IdentityRevision != PolicyIdentityRevision(a) || e.PermissionRevision != p.Permissions.Revision {
		t.Fatalf("accepted team policy not eligible: %+v", e.Result)
	}
	if len(e.DefaultAudience) != 2 {
		t.Fatal("default audience is not the complete current reader set", e.DefaultAudience)
	}
	for _, member := range e.DefaultAudience {
		if member.Kind == "Workload" || member.SubjectID == a.Creator.Subject {
			t.Fatal("the executor or creator joined the audience for creating the capture")
		}
	}
	if len(e.ContributingAssignments) != 1 || e.ContributingAssignments[0] != a.Owners[0] {
		t.Fatal("contributing assignments are not the pinned sponsors")
	}
	if e.ValidUntil.After(i.ValidUntil) || e.ValidUntil.After(p.Permissions.DeniesFreshUntil) {
		t.Fatal("eligibility outlived its inputs")
	}
	if ContextEligibility(i, p.Permissions, target, now).Eligible {
		t.Fatal("the executor gained ordinary personal capture rights")
	}
}

func TestPolicyExecutorCaptureEligibilityFailsClosed(t *testing.T) {
	for _, name := range []string{"sponsor-denied", "executor-denied", "sponsor-removed", "envelope-expired", "binding-expired", "executions-exceed-envelope", "action-not-delegated", "envelope-drops-action", "other-identity", "other-scope", "stale-delegation", "expired-identity", "no-readers"} {
		t.Run(name, func(t *testing.T) {
			i, a, p, target, now := policyCaptureFixture()
			switch name {
			case "sponsor-denied":
				d := p.Permissions.Allows[0]
				p.Permissions.Denies = []CurrentAssignment{d}
			case "executor-denied":
				d := p.Permissions.Allows[0]
				d.Audience.Kind, d.Audience.Issuer, d.Audience.SubjectID, d.Audience.AssignmentID = "Workload", a.Executor.Issuer, a.Executor.Subject, "44444444-4444-4444-4444-444444444444"
				p.Permissions.Denies = []CurrentAssignment{d}
			case "sponsor-removed":
				p.Permissions.Allows = p.Permissions.Allows[1:]
			case "envelope-expired":
				a.NotAfter = now
			case "binding-expired":
				p.NotAfter = now
			case "executions-exceed-envelope":
				p.Envelope.MaxExecutions = a.Limits.MaxExecutions - 1
			case "action-not-delegated":
				a.Actions = []string{"packetCapture"}
			case "envelope-drops-action":
				p.Envelope.AllowedActions = []string{"packetCapture"}
			case "other-identity":
				i.Principal.Subject = "policy:other"
			case "other-scope":
				i.Policy.Digest = artifact.Digest{99}
			case "stale-delegation":
				p.FreshUntil = now
			case "expired-identity":
				i.ValidUntil = now
			case "no-readers":
				p.Permissions.Allows = nil
			}
			if e := PolicyContextEligibility(i, a, p, target, now); e.Eligible {
				t.Fatal("policy executor eligible after", name)
			}
		})
	}
}

func TestPolicyExecutorPrincipalIsExact(t *testing.T) {
	p := PolicyPrincipal("11111111-1111-1111-1111-111111111111", "policy-uid")
	if inst, policy, ok := PolicyExecutor(p); !ok || inst != "11111111-1111-1111-1111-111111111111" || policy != "policy-uid" || !CaptureActor(p) {
		t.Fatal("policy principal not recognized")
	}
	for _, change := range []func(*identity.Principal){
		func(x *identity.Principal) { x.ClientID = "console" },
		func(x *identity.Principal) { x.Kind = identity.Human },
		func(x *identity.Principal) { x.Issuer = "https://id.example.invalid" },
		func(x *identity.Principal) { x.Subject = "user:policy-uid" },
	} {
		x := p
		change(&x)
		if _, _, ok := PolicyExecutor(x); ok {
			t.Fatal("altered principal treated as a policy executor", x)
		}
		if x.Kind == identity.Workload && CaptureActor(x) {
			t.Fatal("arbitrary workload accepted as a capture actor", x)
		}
	}
}
