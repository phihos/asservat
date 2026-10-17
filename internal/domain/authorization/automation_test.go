package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func automationFixture() (AcceptedPolicyAuthority, AutomationProjection, PolicyUse, time.Time) {
	human, q, _, now := fixture()
	d := q.Revision
	d.UID = q.Allows[0].Audience.BasisUID
	a := AcceptedPolicyAuthority{InstallationID: q.Target.ClusterID, PolicyUID: "policy-uid", Creator: human.Principal, Executor: PolicyPrincipal(q.Target.ClusterID, "policy-uid"), ScopeDigest: artifact.Digest{8}, ClusterID: q.Target.ClusterID, NamespaceUID: q.Target.NamespaceUID, WorkloadUID: q.Target.WorkloadUID, Delegation: d, Owners: []artifact.AudienceAssignment{q.Allows[0].Audience}, Actions: []string{"packetCapture"}, Limits: AutomationLimits{10, 1000, 2000}, IssuedAt: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	p := AutomationProjection{InstallationID: a.InstallationID, Delegation: d, Envelope: AutomationEnvelope{[]string{"packetCapture"}, 86400, 10, 1000, 2000}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Permissions: q}
	return a, p, PolicyUse{a.PolicyUID, a.ScopeDigest, q.Target, PolicyIncident}, now
}

func TestTeamPolicySurvivesDepartureWithoutGrantingHumanAccess(t *testing.T) {
	a, p, use, now := automationFixture()
	human, _, e, _ := fixture()
	human.Groups = nil
	if r := Evaluate(human, p.Permissions, ReadApproved, use.Target, &e, now); r.Eligible {
		t.Fatal("departed creator retained read access")
	}
	if r := EvaluatePolicy(a, p, use, now); !r.Eligible || r.Executor == human.Principal || !r.ValidUntil.Equal(p.Permissions.DeniesFreshUntil) {
		t.Fatalf("team policy not independently bounded: %+v", r)
	}
	// Recording the actor does not require a still-valid human token. No token or
	// identity resolver appears in the execution inputs.
	a.Creator.Subject = "former-developer"
	if !EvaluatePolicy(a, p, use, now).Eligible {
		t.Fatal("creator provenance became current execution authority")
	}
}

func TestCurrentDelegationCanUseAnUnchangedHistoricalAssignment(t *testing.T) {
	a, p, use, now := automationFixture()
	// A protected edit keeps the ordinary assignment and its original digest;
	// the new policy independently pins the current delegation revision.
	a.Delegation.Generation++
	a.Delegation.Digest[0]++
	p.Delegation = a.Delegation
	if result := EvaluatePolicy(a, p, use, now); !result.Eligible {
		t.Fatal("current delegation rejected a continuing owner assignment", result)
	}
	a.Owners[0].BasisDigest[0]++
	if EvaluatePolicy(a, p, use, now).Eligible {
		t.Fatal("changed historical assignment digest was accepted")
	}
}

func TestAutomationRejectsEscalationRevocationAndStaleAuthority(t *testing.T) {
	for _, name := range []string{"human-executor", "wrong-policy", "wrong-digest", "other-workload", "other-installation", "changed-binding", "changed-assignment", "lost-owner", "expired", "future", "disabled", "stale-source", "unknown-denies", "stale-denies", "stale-deny-row", "team-deny", "executor-deny", "bytes", "observed-bytes", "count", "lifetime", "action", "download", "personal-owner", "binding-expired", "zero-digest", "duplicate-owner"} {
		t.Run(name, func(t *testing.T) {
			a, p, u, n := automationFixture()
			switch name {
			case "human-executor":
				a.Executor = a.Creator
			case "wrong-policy":
				u.PolicyUID = "other"
			case "wrong-digest":
				u.ScopeDigest = artifact.Digest{9}
			case "other-workload":
				u.Target.WorkloadUID = "other"
			case "other-installation":
				p.InstallationID = "99999999-9999-4999-8999-999999999999"
			case "changed-binding":
				p.Delegation.Generation++
			case "changed-assignment":
				p.Permissions.Allows[0].Audience.AssignmentID = "99999999-9999-4999-8999-999999999999"
			case "lost-owner":
				p.Permissions.Allows = nil
			case "expired":
				a.NotAfter = n
			case "future":
				a.IssuedAt = n.Add(time.Second)
			case "disabled":
				p.Disabled = true
			case "stale-source":
				p.FreshUntil = n
			case "unknown-denies":
				p.Permissions.DeniesComplete = false
			case "stale-denies":
				p.Permissions.DeniesFreshUntil = n
			case "stale-deny-row":
				p.Permissions.Denies = []CurrentAssignment{p.Permissions.Allows[0]}
			case "team-deny":
				d := p.Permissions.Allows[0]
				d.FreshUntil = n.Add(5 * time.Second)
				p.Permissions.Denies = []CurrentAssignment{d}
			case "executor-deny":
				d := p.Permissions.Allows[0]
				d.Audience.Kind = "Workload"
				d.Audience.Issuer = a.Executor.Issuer
				d.Audience.SubjectID = a.Executor.Subject
				d.FreshUntil = n.Add(5 * time.Second)
				p.Permissions.Denies = []CurrentAssignment{d}
			case "bytes":
				p.Envelope.MaxBytes--
			case "observed-bytes":
				p.Envelope.MaxObservedBytes--
			case "count":
				p.Envelope.MaxExecutions--
			case "lifetime":
				p.Envelope.MaxLifetimeSeconds = 10
			case "action":
				p.Envelope.AllowedActions = []string{"liveCore"}
			case "download":
				u.Purpose = "download"
			case "personal-owner":
				a.Owners[0].Kind = "User"
			case "binding-expired":
				p.NotAfter = n
			case "zero-digest":
				a.ScopeDigest = artifact.Digest{}
			case "duplicate-owner":
				a.Owners = append(a.Owners, a.Owners[0])
			}
			if r := EvaluatePolicy(a, p, u, n); r.Eligible {
				t.Fatal("invalid automation accepted", r)
			}
		})
	}
}

func TestPersonalDenyDoesNotRevokeIndependentTeamPolicy(t *testing.T) {
	a, p, u, n := automationFixture()
	d := p.Permissions.Allows[0]
	d.Audience.Kind = "User"
	d.Audience.SubjectID = a.Creator.Subject
	d.FreshUntil = n.Add(5 * time.Second)
	p.Permissions.Denies = []CurrentAssignment{d}
	if !EvaluatePolicy(a, p, u, n).Eligible {
		t.Fatal("personal departure stopped independent team authorization")
	}
	p.NotAfter = n.Add(time.Second)
	if r := EvaluatePolicy(a, p, u, n); !r.ValidUntil.Equal(p.NotAfter) {
		t.Fatal("binding expiry extended")
	}
}

func TestAcceptanceRequiresCurrentAuthorAndIndependentDelegation(t *testing.T) {
	a, p, u, n := automationFixture()
	human, _, _, _ := fixture()
	if !ValidatePolicyAcceptance(human, a, p, u, n).Eligible {
		t.Fatal("authorized author rejected")
	}
	a.Creator.Subject = "original-creator"
	if !ValidatePolicyAcceptance(human, a, p, u, n).Eligible {
		t.Fatal("current team editor rejected because creator differs")
	}
	for _, change := range []string{"departed", "non-human", "stale", "outside-team", "human-exec-only"} {
		t.Run(change, func(t *testing.T) {
			a, p, u, n := automationFixture()
			h, _, _, _ := fixture()
			switch change {
			case "departed":
				h.Groups = nil
			case "non-human":
				h.Principal.Kind = "workload"
			case "stale":
				h.ValidUntil = n
			case "outside-team":
				a.Owners[0].SubjectID = "other-team"
			case "human-exec-only":
				p.Envelope = AutomationEnvelope{}
			}
			if ValidatePolicyAcceptance(h, a, p, u, n).Eligible {
				t.Fatal("unauthorized delegation accepted")
			}
		})
	}
}

func TestOngoingAcquisitionRequiresObservationDelegation(t *testing.T) {
	a, p, u, n := automationFixture()
	a.Limits.MaxObservedBytes = 0
	for _, purpose := range []PolicyPurpose{PolicyArm, PolicyRenew} {
		u.Purpose = purpose
		if EvaluatePolicy(a, p, u, n).Eligible {
			t.Fatal("zero observation budget armed a source")
		}
	}
}

func TestEveryPinnedSponsorMustRetainItsOriginalAssignment(t *testing.T) {
	a, p, u, n := automationFixture()
	second := p.Permissions.Allows[0]
	second.Audience.SubjectID = "team-b"
	second.Audience.AssignmentID = "44444444-4444-4444-8444-444444444444"
	a.Owners = append(a.Owners, second.Audience)
	p.Permissions.Allows = append(p.Permissions.Allows, second)
	if !EvaluatePolicy(a, p, u, n).Eligible {
		t.Fatal("valid multiple sponsorship rejected")
	}
	p.Permissions.Allows = p.Permissions.Allows[:1]
	if EvaluatePolicy(a, p, u, n).Eligible {
		t.Fatal("missing pinned sponsorship ignored")
	}
}
