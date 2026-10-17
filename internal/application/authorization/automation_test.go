package authorization

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type automationAccepted struct{ a value.AcceptedPolicySnapshot }

func (r automationAccepted) AcceptedPolicyAuthority(context.Context, string) (value.AcceptedPolicySnapshot, error) {
	return r.a, nil
}

type automationCurrent struct {
	p     value.AutomationProjection
	delay func()
}

func (r automationCurrent) PolicyAutomationAuthority(context.Context, value.AcceptedPolicyAuthority, value.Target) (value.AutomationProjection, error) {
	if r.delay != nil {
		r.delay()
	}
	return r.p, nil
}
func TestAutomationRechecksDeadlinesAfterCurrentAuthorityRead(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 2 * time.Second, 6 * time.Second, -time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			n := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
			cluster := "11111111-1111-4111-8111-111111111111"
			target := value.Target{ClusterID: cluster, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod"}
			rev := identity.Revision{UID: "binding", Generation: 1, Digest: [32]byte{1}}
			owner := artifact.AudienceAssignment{Kind: "Group", Issuer: "https://id.example.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", BasisDigest: artifact.Digest{1}, AssignmentID: "22222222-2222-4222-8222-222222222222"}
			a := value.AcceptedPolicyAuthority{InstallationID: cluster, PolicyUID: "policy", Creator: identity.Principal{Issuer: owner.Issuer, Subject: "creator", ClientID: "console", Kind: identity.Human}, Executor: value.PolicyPrincipal(cluster, "policy"), ScopeDigest: artifact.Digest{2}, ClusterID: cluster, NamespaceUID: "ns", WorkloadUID: "workload", Delegation: rev, Owners: []artifact.AudienceAssignment{owner}, Actions: []string{"logs"}, Limits: value.AutomationLimits{MaxExecutions: 10, MaxBytes: 100, MaxObservedBytes: 0}, IssuedAt: n, NotAfter: n.Add(time.Hour)}
			p := value.AutomationProjection{InstallationID: cluster, Delegation: rev, Envelope: value.AutomationEnvelope{AllowedActions: []string{"logs"}, MaxLifetimeSeconds: 3600, MaxExecutions: 10, MaxBytes: 100}, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), Permissions: value.Projection{Target: target, Revision: rev, ObservedAt: n, FreshUntil: n.Add(30 * time.Second), DeniesComplete: true, DeniesObservedAt: n, DeniesFreshUntil: n.Add(5 * time.Second), Allows: []value.CurrentAssignment{{Audience: owner, ObservedAt: n, FreshUntil: n.Add(30 * time.Second)}}}}
			service := AutomationEvaluator{Accepted: automationAccepted{value.AcceptedPolicySnapshot{Authority: a, ObservedAt: n, FreshUntil: n.Add(time.Second)}}, Current: automationCurrent{p, func() { n = n.Add(elapsed) }}, Now: func() time.Time { return n }}
			got := service.Eligibility(context.Background(), value.PolicyUse{PolicyUID: "policy", ScopeDigest: a.ScopeDigest, Target: target, Purpose: value.PolicyIncident})
			if got.Eligible != (elapsed == 0) {
				t.Fatalf("stale or rebound authority: %+v", got)
			}
		})
	}
}
