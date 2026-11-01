package integration

import (
	"fmt"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// The same sponsor selector used by real SQL preparation must retain the human's
// actual membership while the independent default audience retains all readers.
func TestPolicyRecorderSponsorKeepsHumanMembershipAndWholeAudience(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	installation, cluster, policy := custodyID(), custodyID(), custodyID()
	revision := identity.Revision{UID: "delegation", Generation: 1, Digest: artifact.Digest{1}}
	author := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: revision, Scopes: []string{"evidence:capture"}, Groups: []string{"maintainers"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
	target := authorization.Target{ClusterID: cluster, NamespaceUID: custodyID(), WorkloadUID: custodyID(), PodUID: custodyID()}
	p := authorization.Projection{Target: target, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second)}
	for i := 0; i < 32; i++ {
		subject := "maintainers"
		if i > 0 {
			subject = fmt.Sprintf("other-%d", i)
		}
		a := artifact.AudienceAssignment{Kind: "Group", Issuer: author.Principal.Issuer, SubjectID: subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: revision.UID, BasisDigest: revision.Digest, AssignmentID: custodyID()}
		p.Allows = append(p.Allows, authorization.CurrentAssignment{Audience: a, ObservedAt: now, FreshUntil: p.FreshUntil})
	}
	a := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: policy, Creator: author.Principal, Executor: authorization.PolicyPrincipal(installation, policy), ScopeDigest: artifact.Digest{2}, ClusterID: cluster, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID, Delegation: revision, Owners: []artifact.AudienceAssignment{policyRecorderSponsor(author, p, revision.UID)}, Actions: []string{"packetCapture"}, Limits: authorization.AutomationLimits{MaxExecutions: 10, MaxBytes: 64 << 20, MaxObservedBytes: 1 << 30}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
	w := authorization.WorkloadTarget{ClusterID: cluster, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
	wp := authorization.WorkloadAutomationProjection{InstallationID: installation, Delegation: revision, Envelope: authorization.AutomationEnvelope{AllowedActions: a.Actions, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 64 << 20, MaxObservedBytes: 1 << 30}, ObservedAt: now, FreshUntil: p.FreshUntil, Permissions: authorization.WorkloadProjection{Target: w, Revision: revision, ObservedAt: now, FreshUntil: p.FreshUntil, DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: p.DeniesFreshUntil, Allows: p.Allows}}
	if result := authorization.ValidatePolicyWorkloadAcceptance(author, a, wp, now); !result.Eligible {
		t.Fatal("real policy acceptance refused fixture sponsor", result.Reason)
	}
	ap := authorization.AutomationProjection{InstallationID: installation, Delegation: revision, Envelope: wp.Envelope, ObservedAt: now, FreshUntil: p.FreshUntil, Permissions: p}
	e := authorization.PolicyContextEligibility(authorization.PolicyExecutorIdentity(a, now, p.FreshUntil), a, ap, target, now)
	if !e.Eligible || len(e.DefaultAudience) != 32 {
		t.Fatal("fixture sponsor narrowed actual default audience", e.Reason, len(e.DefaultAudience))
	}
	author.Groups = nil
	a.Owners = []artifact.AudienceAssignment{policyRecorderSponsor(author, p, revision.UID)}
	if authorization.ValidatePolicyWorkloadAcceptance(author, a, wp, now).Eligible {
		t.Fatal("nonmember acquired fixture sponsorship")
	}
}

func TestPolicyRecorderCaseOwnsMutablePermissionInput(t *testing.T) {
	previous := cfg.PermissionBatch{ExpectedSequence: 5, Bases: []cfg.PermissionBasis{{Resource: cfg.Resource{Generation: 1}}}}
	next := policyRecorderCloneBatch(previous)
	next.Bases[0].Resource.Generation++
	next.ExpectedSequence++
	if previous.Bases[0].Resource.Generation != 1 || previous.ExpectedSequence != 5 {
		t.Fatal("new case changed previous accepted permission receipt")
	}
}
