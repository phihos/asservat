package authorization

import (
	"errors"
	"testing"
)

func TestPolicyAttachmentIsExplicitControlWithoutReissuingAuthority(t *testing.T) {
	g, p, _, now := approvedPolicyUseFixture(t)
	if err := CheckPolicyGrantAttachment(g, p, "", now); err != nil {
		t.Fatal("explicit unpinned manager attachment", err)
	}
	if err := CheckPolicyGrantAttachment(g, p, g.ID, now); err != nil {
		t.Fatal("exact authored pointer", err)
	}
	if err := CheckPolicyGrantAttachment(g, p, "00000000-0000-4000-8000-000000000099", now); !errors.Is(err, ErrGrantScope) {
		t.Fatal("authored pin overridden", err)
	}
	a := PolicyGrantAttachment{ID: "00000000-0000-4000-8000-000000000098", RootID: g.RootID, InstallationID: p.InstallationID, PolicyUID: p.PolicyUID, AcceptanceID: "00000000-0000-4000-8000-000000000097", GrantID: g.ID, AuthorityDigest: p.ScopeDigest, Actor: g.Decision.Approver, AttachedAt: now}
	if !a.Matches(g.RootID, a.AcceptanceID, p, "") {
		t.Fatal("original attachment unavailable")
	}
	if a.Matches(g.RootID, a.AcceptanceID, p, g.ID) {
		t.Fatal("new authored pin silently reused old unpinned control")
	}
	a.AuthoredGrantRef = g.ID
	if !a.Matches(g.RootID, a.AcceptanceID, p, g.ID) {
		t.Fatal("explicit reconciliation not recognized")
	}
	if a.Matches(g.RootID, "00000000-0000-4000-8000-000000000096", p, g.ID) {
		t.Fatal("attachment transferred across acceptance")
	}
	g.PolicySpend.Executions = g.Policy.Limits.MaxExecutions
	if err := CheckPolicyGrantAttachment(g, p, g.ID, now); err != nil {
		t.Fatal("exact exhausted attachment receipt became unrecoverable", err)
	}
	if g.Phase(now) != GrantExhausted {
		t.Fatal("attachment reset spend")
	}
}
