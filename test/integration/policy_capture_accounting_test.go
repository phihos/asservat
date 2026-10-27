package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL-only review/attachment fixture: current identity and immutable review
// representation are synthetic. It does not supply public review authority.
func attachPolicyAccountingGrant(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, a authorization.AcceptedPolicyAuthority) string {
	t.Helper()
	role := narrowRole(t, ctx, admin, "policy_accounting_grant_", "synthetic-accounting", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing hub duty")
		}
		return grants
	})
	hub := poolFor(role, "synthetic-accounting")
	defer hub.Close()
	policies, err := postgres.NewPolicies(ctx, hub, s.a.RootID, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := postgres.NewRecoveryTransactionGuard(s.a.RootID, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.NewAccessGrants(ctx, hub, s.a.RootID, guard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	settings := identity.PolicyGrantSettingsObservation{Issuer: a.Creator.Issuer, Revision: identity.Revision{UID: "accounting-policy-period", Generation: 1, Digest: artifact.Digest{77}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Values: identity.PolicyGrantApproval{DefaultAge: time.Hour, MaxAge: time.Hour, RenewalNotice: time.Minute}}
	// Protected settings retain the independently provisioned existing duty;
	// the ordinary hub must not gain permission to accept its own maxima.
	settingsRole := narrowRole(t, ctx, admin, "policy_accounting_settings_", "synthetic-accounting-settings", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("permission-accept", role)
		if !ok {
			t.Fatal("missing protected settings duty")
		}
		return grants
	})
	settingsPool := poolFor(settingsRole, "synthetic-accounting-settings")
	defer settingsPool.Close()
	settingsWriter, err := postgres.NewPolicies(ctx, settingsPool, s.a.RootID, a.InstallationID)
	if err != nil {
		t.Fatal("settings facet", err)
	}
	if err = settingsWriter.AcceptPolicyGrantSettings(ctx, settings); err != nil {
		t.Fatal("protected settings acceptance", err)
	}
	limits := authorization.AutomationLimits{MaxExecutions: 4, MaxBytes: 4 * artifact.MaxContextBytes}
	g := authorization.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: authorization.GrantPolicy, Requester: a.Creator, ExecutionDigest: a.ScopeDigest, DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: "pod-status", Code: "synthetic-component-review"}}, Scope: []byte(`{"fixture":"accepted-context-policy"}`), Review: []byte(`{}`), Lifetime: time.Hour, Revision: 1, Policy: &authorization.PolicyGrantScope{Authority: a, RecipeDigest: planning.RecipeDigest(), Limits: limits, ApprovalPolicyRef: settings.Revision, ApprovalMaxAge: time.Hour}}
	g.ReviewDigest = app.ReviewDigest(g, g.Review)
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err = store.RequestGrant(ctx, app.StoredGrantRequest{Grant: g, IdempotencyKey: "accounting-review", RequestDigest: artifact.Digest{78}}, recovery)
	if err != nil {
		t.Fatal("policy grant request", err)
	}
	g, _, err = store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: g.ID, Approver: identity.Principal{Issuer: a.Creator.Issuer, Subject: "independent-component-reviewer", ClientID: "review-console", Kind: identity.Human}, Approve: true, Reason: "synthetic SQL review", ACR: "fixture-step-up", AuthTime: now, IdempotencyKey: "accounting-approval"}, recovery)
	if err != nil {
		t.Fatal("independent component decision", err)
	}
	actor := identity.Identity{Principal: a.Creator, Scopes: []string{"evidence:read", "evidence:capture"}, Groups: []string{"maintainers"}, Policy: s.a.Eligibility.VerifiedIdentity.Policy, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	if _, _, err = policies.AttachPolicyGrant(ctx, app.PolicyGrantAttachmentInput{ID: custodyID(), PolicyUID: a.PolicyUID, GrantID: g.ID, IdempotencyKey: "accounting-attachment", Actor: actor, Recovery: recovery}); err != nil {
		t.Fatal("current manager attachment", err)
	}
	return g.ID
}
