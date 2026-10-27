package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Component proof: actual grant/settings transactions and compiled role grants,
// with the parent's real acceptance/audit and explicit synthetic source/KMS.
// It does not qualify public requester/reviewer authentication or recording.
func qualifyPolicyGrantPersistence(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, root string, authority authorization.AcceptedPolicyAuthority, acceptance string, scope []byte, recovery artifact.RecoveryProof) {
	t.Helper()
	rolePool := func(purpose, prefix string) *pgxpool.Pool {
		t.Helper()
		role := narrowRole(t, ctx, admin, prefix, "synthetic-policy-grant", func(role string) []string {
			grants, ok := postgres.PublicRuntimeRoleGrantSQL(purpose, role)
			if !ok {
				t.Fatal("missing compiled purpose", purpose)
			}
			return grants
		})
		return poolFor(role, "synthetic-policy-grant")
	}
	hub := rolePool("hub-runtime", "policy_grant_hub_")
	defer hub.Close()
	worker := rolePool("permission-accept", "policy_grant_settings_")
	defer worker.Close()
	projection, err := postgres.NewPolicies(ctx, worker, root, authority.InstallationID)
	if err != nil {
		t.Fatal("settings facet", err)
	}
	guard, err := postgres.NewRecoveryTransactionGuard(root, authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgres.NewAccessGrants(ctx, hub, root, guard)
	if err != nil {
		t.Fatal("grant facet", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	settings := identity.PolicyGrantSettingsObservation{Issuer: authority.Creator.Issuer, Revision: identity.Revision{UID: "protected-policy-periods", Generation: 1, Digest: artifact.Digest{8}},
		ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Values: identity.PolicyGrantApproval{DefaultAge: 30 * time.Minute, MaxAge: time.Hour, RenewalNotice: time.Minute}}
	if err = projection.AcceptPolicyGrantSettings(ctx, settings); err != nil {
		t.Fatal("accept protected periods", err)
	}
	if got, err := store.PolicyApprovalSettings(ctx); err != nil || got.Revision != settings.Revision || got.Values != authorization.PolicyApprovalSettings(settings.Values) || !got.FreshUntil.Equal(settings.FreshUntil) {
		t.Fatal("accepted projection changed original observation", got, err)
	}
	request := func(actor identity.Principal) app.StoredGrantRequest {
		t.Helper()
		limits := authorization.AutomationLimits{MaxExecutions: 2, MaxBytes: 256}
		input := app.PolicyGrantRequestInput{PolicyUID: authority.PolicyUID, IdempotencyKey: "one-original-intent", Lifetime: 30 * time.Minute, Limits: limits}
		g := authorization.Grant{ID: custodyID(), RootID: root, Kind: authorization.GrantPolicy, Requester: actor, ExecutionDigest: authority.ScopeDigest,
			DataClass: "extract", Reasons: []authorization.SensitiveReason{{ActionID: "packets", Code: "rawBytePredicate"}}, Scope: scope, Review: []byte(`{}`),
			Lifetime: input.Lifetime, Revision: 1, Policy: &authorization.PolicyGrantScope{Authority: authority, RecipeDigest: artifact.Digest{9}, Limits: limits,
				ApprovalPolicyRef: settings.Revision, ApprovalMaxAge: settings.Values.MaxAge}}
		g.ReviewDigest = app.ReviewDigest(g, g.Review)
		return app.StoredGrantRequest{Grant: g, IdempotencyKey: input.IdempotencyKey, RequestDigest: app.PolicyGrantRequestDigest(actor, input)}
	}
	original := request(authority.Creator)
	g, replay, err := store.RequestGrant(ctx, original, recovery)
	if err != nil || replay || !g.Valid() || g.Target != (authorization.Target{}) || g.Policy == nil || g.ResultAccess != nil ||
		!g.PolicyNotAfter.Equal(g.RequestedAt.Add(original.Grant.Lifetime)) {
		t.Fatal("original policy request", g, replay, err)
	}
	var actualAcceptance string
	if err = admin.QueryRow(ctx, `SELECT policy_acceptance_id::text FROM access_grant WHERE id=$1`, g.ID).Scan(&actualAcceptance); err != nil || actualAcceptance != acceptance {
		t.Fatal("request did not pin actual current acceptance", err)
	}
	// Clone only ordinary columns into a new request. Generated columns must
	// be computed by PostgreSQL, so these refusals exercise actual constraints.
	var columns string
	if err = admin.QueryRow(ctx, `SELECT string_agg(quote_ident(attname),',' ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.access_grant'::regclass AND attnum>0 AND NOT attisdropped AND attgenerated=''`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	for name, patch := range map[string]map[string]any{
		"fake Pod":                  {"pod_uid": "invented"},
		"fake capture":              {"capture_id": custodyID()},
		"fake preview":              {"preview_id": custodyID()},
		"missing policy":            {"policy_uid": nil},
		"missing expiry":            {"policy_not_after": nil},
		"unapproved spend":          {"policy_executions_spent": 1},
		"personal pool":             {"max_bytes": 1},
		"invalid requester kind":    {"requester_kind": "policyExecutor"},
		"caller-selected actor key": {"requester_key": "\\x0000000000000000000000000000000000000000000000000000000000000000"},
	} {
		patch["id"], patch["idempotency_key"] = custodyID(), custodyID()
		b, err := json.Marshal(patch)
		if err != nil {
			t.Fatal(err)
		}
		_, err = admin.Exec(ctx, `INSERT INTO access_grant(`+columns+`) SELECT `+columns+` FROM jsonb_populate_record(NULL::access_grant,(SELECT to_jsonb(g) FROM access_grant g WHERE id=$1)||$2::jsonb)`, g.ID, b)
		var check *pgconn.PgError
		if !errors.As(err, &check) || check.Code != "23514" {
			t.Fatal("conditional shape did not refuse", name, err)
		}
	}
	for _, actor := range []identity.Principal{
		{Issuer: authority.Creator.Issuer, Subject: authority.Creator.Subject, ClientID: "other-authenticated-client", Kind: identity.Human},
		{Issuer: authority.Creator.Issuer, Subject: authority.Creator.Subject, ClientID: authority.Creator.ClientID, Kind: identity.Workload},
		{Issuer: "https://id.example.test", Subject: "développeur-支付", ClientID: "console-é-支付", Kind: identity.Human},
	} {
		x, replay, err := store.RequestGrant(ctx, request(actor), recovery)
		if err != nil || replay || x.ID == g.ID || x.Requester != actor {
			t.Fatal("different full principal inherited original journal", x, replay, err)
		}
		if actor.Subject == "développeur-支付" {
			var key string
			if err = admin.QueryRow(ctx, `SELECT encode(requester_key,'hex') FROM access_grant WHERE id=$1`, x.ID).Scan(&key); err != nil || key != "1a710aa21e71148b6be54f670a1b6aca0ff6aadec6b7e1d82d71ddef71a2c4f7" {
				t.Fatal("server-computed UTF-8 key differs from Go golden", key, err)
			}
			in := request(actor)
			got, found, err := store.LookupPolicyGrantRequest(ctx, app.PolicyGrantRequestLookup{Requester: actor, PolicyUID: authority.PolicyUID, IdempotencyKey: in.IdempotencyKey, InputDigest: in.RequestDigest})
			if err != nil || !found || got.ID != x.ID {
				t.Fatal("Go/SQL multibyte key could not recover exact original", err)
			}
		}
	}
	conflict := original
	conflict.RequestDigest[0]++
	if _, _, err = store.RequestGrant(ctx, conflict, recovery); !errors.Is(err, app.ErrGrantConflict) {
		t.Fatal("changed original caller choices did not conflict", err)
	}
	// Let the original request age before approving under its original maximum.
	// A later one-second ceiling will then precede this historical decision.
	timer := time.NewTimer(time.Until(g.RequestedAt.Add(1100 * time.Millisecond)))
	select {
	case <-ctx.Done():
		timer.Stop()
		t.Fatal(ctx.Err())
	case <-timer.C:
	}
	approver := identity.Principal{Issuer: authority.Creator.Issuer, Subject: "independent-reviewer", ClientID: "review-console", Kind: identity.Human}
	g, replay, err = store.DecideGrant(ctx, app.GrantDecisionInput{GrantID: g.ID, Approver: approver, Approve: true, Reason: "synthetic SQL component review", ACR: "fixture-step-up", AuthTime: now, IdempotencyKey: "one-review"}, recovery)
	if err != nil || replay || !g.ExpiresAt.Equal(g.PolicyNotAfter) {
		t.Fatal("decision must retain original request anchor", g, replay, err)
	}
	settings.Revision.Generation++
	settings.Revision.Digest[0]++
	settings.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	settings.FreshUntil = settings.ObservedAt.Add(30 * time.Second)
	settings.Values = identity.PolicyGrantApproval{DefaultAge: time.Second, MaxAge: time.Second, RenewalNotice: time.Second}
	if err = projection.AcceptPolicyGrantSettings(ctx, settings); err != nil {
		t.Fatal("atomic lower maximum", err)
	}
	lowered, err := store.Grant(ctx, g.ID)
	if err != nil || !lowered.Valid() || lowered.Revision != g.Revision || !lowered.ExpiresAt.Equal(g.RequestedAt.Add(time.Second)) ||
		!lowered.ExpiresAt.Before(lowered.Decision.DecidedAt) || lowered.Phase(time.Now()) != authorization.GrantExpired || lowered.PolicySpend != g.PolicySpend {
		t.Fatal("historical approval/counters were rewritten or invalidated by clamp", lowered, err)
	}
	settings.Revision.Generation++
	settings.Revision.Digest[0]++
	settings.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	settings.FreshUntil = settings.ObservedAt.Add(30 * time.Second)
	settings.Values = identity.PolicyGrantApproval{DefaultAge: time.Hour, MaxAge: time.Hour, RenewalNotice: time.Minute}
	if err = projection.AcceptPolicyGrantSettings(ctx, settings); err != nil {
		t.Fatal("later maximum raise", err)
	}
	restarted, err := postgres.NewAccessGrants(ctx, hub, root, guard)
	if err != nil {
		t.Fatal(err)
	}
	recovered, found, err := restarted.LookupPolicyGrantRequest(ctx, app.PolicyGrantRequestLookup{Requester: original.Grant.Requester, PolicyUID: authority.PolicyUID, IdempotencyKey: original.IdempotencyKey, InputDigest: original.RequestDigest})
	if err != nil || !found || recovered.ID != g.ID || !recovered.RequestedAt.Equal(g.RequestedAt) || !recovered.ExpiresAt.Equal(lowered.ExpiresAt) ||
		recovered.Policy.ApprovalMaxAge != original.Grant.Policy.ApprovalMaxAge || recovered.Policy.RecipeDigest != original.Grant.Policy.RecipeDigest || recovered.PolicySpend != lowered.PolicySpend {
		t.Fatal("restart/lost reply refilled or reinterpreted original request", recovered, found, err)
	}
	var unclamped int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM access_grant WHERE root_id=$1 AND kind='policy' AND policy_not_after<>requested_at+interval '1 second'`, root).Scan(&unclamped); err != nil || unclamped != 0 {
		t.Fatal("unused/pending grants escaped lower-period clamp", unclamped, err)
	}
	// The settings credential may clamp deadlines, never inspect reviews or
	// mint decisions, refill spend, or edit original request provenance.
	for _, sql := range []string{
		`SELECT review FROM access_grant`,
		`UPDATE access_grant SET policy_bytes_spent=1`,
		`UPDATE access_grant SET requested_at=clock_timestamp()`,
		`UPDATE access_grant SET decision='approved'`,
	} {
		if _, err := worker.Exec(ctx, sql); err == nil {
			t.Fatal("settings role exceeded its closed facet", sql)
		}
	}
	// Actual Down refuses all policy survivors without deleting/rekeying them.
	raw, err := os.ReadFile("../../migrations/00102_policy_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(raw), "-- +goose Down")
	if len(parts) != 2 {
		t.Fatal("missing Down body")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, refused := tx.Exec(ctx, parts[1])
	rollback := tx.Rollback(ctx)
	var incompatible *pgconn.PgError
	if !errors.As(refused, &incompatible) || incompatible.Code != "23514" || rollback != nil {
		t.Fatal("incompatible Down must refuse atomically", refused, rollback)
	}
	if after, err := store.Grant(ctx, g.ID); err != nil || after.ID != recovered.ID || !after.ExpiresAt.Equal(recovered.ExpiresAt) {
		t.Fatal("failed rollback changed a surviving grant", err)
	}
}
