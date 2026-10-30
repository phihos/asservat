package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQL-only review/attachment fixture: current identity and immutable review
// representation are synthetic. It does not supply public review authority.
func attachPolicyAccountingGrant(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, a authorization.AcceptedPolicyAuthority, scope []byte, key string, recorder ...planvalue.PolicyRecorderConfiguration) string {
	t.Helper()
	return attachPolicyAccountingGrantMode(t, ctx, admin, poolFor, s, a, scope, key, true, recorder...)
}

// Ordinary require-all approval covers saves, without a raw observation pool.
// Request, independent SQL decision and attachment remain component fixtures
// below the public audited grant workflow, as in the legacy wrapper above.
func attachOrdinaryPolicyAccountingGrant(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, a authorization.AcceptedPolicyAuthority, scope []byte, key string, recorder planvalue.PolicyRecorderConfiguration) string {
	t.Helper()
	return attachPolicyAccountingGrantMode(t, ctx, admin, poolFor, s, a, scope, key, false, recorder)
}

func attachPolicyAccountingGrantMode(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, a authorization.AcceptedPolicyAuthority, scope []byte, key string, observation bool, recorder ...planvalue.PolicyRecorderConfiguration) string {
	t.Helper()
	// Role labels may repeat, but reviewed operations for distinct policies must
	// use distinct original request keys under the same root and human actor.
	requestKey := key + ":" + a.PolicyUID
	role := narrowRole(t, ctx, admin, "policy_accounting_grant_"+key+"_", "synthetic-accounting", func(role string) []string {
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
	settingsRole := narrowRole(t, ctx, admin, "policy_accounting_settings_"+key+"_", "synthetic-accounting-settings", func(role string) []string {
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
	g := authorization.Grant{ID: custodyID(), RootID: s.a.RootID, Kind: authorization.GrantPolicy, Requester: a.Creator, ExecutionDigest: a.ScopeDigest, DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: "pod-status", Code: "synthetic-component-review"}}, Scope: scope, Review: []byte(`{}`), Lifetime: time.Hour, Revision: 1, Policy: &authorization.PolicyGrantScope{Authority: a, RecipeDigest: planning.RecipeDigest(), Limits: limits, ApprovalPolicyRef: settings.Revision, ApprovalMaxAge: time.Hour}}
	if len(recorder) == 1 {
		g.Policy.RecipeDigest = recorder[0].RecipeDigest
		g.Policy.Limits.MaxBytes = 4 * artifact.RecordingNativeLimit
		// Only the explicit SQL observation component case provisions this
		// synthetic reviewed pool; ordinary recorder fixtures remain unchanged.
		if observation && a.Limits.MaxObservedBytes > 0 {
			timeout, err := time.ParseDuration(recorder[0].Action.Timeout)
			if err != nil {
				t.Fatal(err)
			}
			g.Policy.Limits.MaxObservedBytes = a.Limits.MaxObservedBytes
			g.Policy.Observation = &authorization.ObservationLimits{MaxSessionSeconds: int64(timeout / time.Second), MaxObservedBytes: a.Limits.MaxObservedBytes, MaxBytesPerSecond: planvalue.SensitiveMaxBytesPerSecond, MaxConcurrentSessions: 1}
		}
	}
	g.ReviewDigest = app.ReviewDigest(g, g.Review)
	blueprint := g
	blueprint.RequestedAt = now
	blueprint.ReviewUntil = now.Add(authorization.GrantReviewWindow)
	blueprint.PolicyNotAfter = identity.Earlier(now.Add(g.Lifetime), a.NotAfter)
	if !blueprint.Valid() || sha256.Sum256(scope) != g.ExecutionDigest || app.ReviewDigest(g, g.Review) != g.ReviewDigest {
		t.Fatal("synthetic grant blueprint violates immutable domain/scope/review bindings")
	}
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g, _, err = store.RequestGrant(ctx, app.StoredGrantRequest{Grant: g, IdempotencyKey: requestKey, RequestDigest: app.PolicyGrantRequestDigest(a.Creator, app.PolicyGrantRequestInput{PolicyUID: a.PolicyUID, PolicyName: "restarts", IdempotencyKey: requestKey, Lifetime: g.Lifetime, Limits: g.Policy.Limits})}, recovery)
	if err != nil {
		t.Fatal("policy grant request", err)
	}
	g, _, err = store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: g.ID, Approver: identity.Principal{Issuer: a.Creator.Issuer, Subject: "independent-component-reviewer", ClientID: "review-console", Kind: identity.Human}, Approve: true, Reason: "synthetic SQL review", ACR: "fixture-step-up", AuthTime: now, IdempotencyKey: requestKey + "-approval"}, recovery)
	if err != nil {
		t.Fatal("independent component decision", err)
	}
	if !observation && (g.Policy == nil || g.Policy.Observation != nil || g.Policy.Authority.ScopeDigest != a.ScopeDigest || g.Policy.Authority.Limits != a.Limits) {
		t.Fatal("ordinary grant changed actual authority or acquired raw observation credit")
	}
	actor := identity.Identity{Principal: a.Creator, Scopes: []string{"evidence:read", "evidence:capture"}, Groups: []string{"maintainers"}, Policy: s.a.Eligibility.VerifiedIdentity.Policy, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	if _, _, err = policies.AttachPolicyGrant(ctx, app.PolicyGrantAttachmentInput{ID: custodyID(), PolicyUID: a.PolicyUID, GrantID: g.ID, IdempotencyKey: requestKey + "-attachment", Actor: actor, Recovery: recovery}); err != nil {
		t.Fatal("current manager attachment", err)
	}
	return g.ID
}

func qualifyOriginalPolicyGrantAcquisition(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, a authorization.AcceptedPolicyAuthority, c capture.Accepted, oldGrant string, replace func() string, refresh func()) {
	t.Helper()
	role := narrowRole(t, ctx, admin, "policy_accounting_api_", "synthetic-accounting-api", func(role string) []string {
		// API execution is a shared hub duty, not a separately installed role.
		// Exercise its production adapter with the actual compiled hub union.
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing installed hub role")
		}
		return grants
	})
	pool := poolFor(role, "synthetic-accounting-api")
	defer pool.Close()
	statuses, err := postgres.NewPolicyTriggers(ctx, pool, s.a.RootID, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	status, err := statuses.Status(ctx, a.PolicyUID)
	if err != nil || status.ActiveID == "" || status.ExecutionsSpent != 5 || status.CollectedBytesSpent != 4*artifact.MaxContextBytes || status.MaxCollectedBytes != a.Limits.MaxBytes || status.ObservedBytesSpent != 0 || status.MaxObservedBytes != a.Limits.MaxObservedBytes {
		t.Fatal("shared accepted budget status differs from actual charged pool", status, err)
	}
	reader, err := postgres.NewAPIContextExecutions(ctx, pool, s.a.RootID, postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard})
	if err != nil {
		t.Fatal(err)
	}
	read := func() error {
		refresh()
		proof, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		_, err = reader.ReadAPIContextWork(ctx, c.CaptureID, authorization.PolicyExecutorIdentity(a, now, now.Add(5*time.Second)), proof)
		return err
	}
	if err = read(); err != nil {
		t.Fatal("original spent grant did not cover its prepaid API work", err)
	}
	replacement := replace()
	if replacement == oldGrant {
		t.Fatal("replacement silently replayed the original request")
	}
	if err = read(); err != nil {
		t.Fatal("attachment replacement rebound or stopped original prepaid work", err)
	}
	hubRole := narrowRole(t, ctx, admin, "policy_accounting_revoke_", "synthetic-accounting-revoke", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing hub duty")
		}
		return grants
	})
	hub := poolFor(hubRole, "synthetic-accounting-revoke")
	defer hub.Close()
	guard, err := postgres.NewRecoveryTransactionGuard(s.a.RootID, a.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := postgres.NewAccessGrants(ctx, hub, s.a.RootID, guard)
	if err != nil {
		t.Fatal(err)
	}
	original, err := grants.Grant(ctx, oldGrant)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = grants.RevokeGrant(ctx, app.GrantRevocationInput{GrantID: oldGrant, Revoker: a.Creator, ExpectedRevision: original.Revision, IdempotencyKey: "revoke-original-after-replacement"}, proof); err != nil {
		t.Fatal(err)
	}
	err = read()
	var step interface{ FixedStep() string }
	if !errors.Is(err, capture.ErrDenied) || !errors.As(err, &step) || step.FixedStep() != "approval" {
		t.Fatal("new attachment revived revoked original acquisition", err)
	}
	var bound string
	var bytes int64
	if err = admin.QueryRow(ctx, `SELECT grant_id::text,reserved_bytes FROM policy_occurrence WHERE reserved_capture_id=$1`, c.CaptureID).Scan(&bound, &bytes); err != nil || bound != oldGrant || bytes != artifact.MaxContextBytes {
		t.Fatal("original reservation changed after replacement/revocation", bound, bytes, err)
	}
	newer, err := grants.Grant(ctx, replacement)
	if err != nil || newer.Phase(time.Now()) != authorization.GrantApproved || newer.PolicySpend != (authorization.PolicyGrantSpend{}) {
		t.Fatal("old work consumed or revoked replacement grant", newer.PolicySpend, err)
	}
	retained, err := grants.Grant(ctx, oldGrant)
	if err != nil || retained.PolicySpend != original.PolicySpend {
		t.Fatal("revocation refunded original uncertain spend", err)
	}
	t.Log("original-grant acquisition: positive before/after attachment replacement; original revocation denied at approval; tuple and both spent pools unchanged")
}
