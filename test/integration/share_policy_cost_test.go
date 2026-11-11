package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Only closures from the existing accepted policy/admission/publication fixture.
// No table-copy producer or fabricated capture/audit/share links are introduced.
type policyShareCostFixture struct {
	Scenario captureAdmissionScenario
	Creator  identity.Principal
	Groups   []string
	Accept   func() string
	Grant    func()
	Admit    func() capture.Accepted
	Prepare  func(capture.Accepted, bool) captureShareFixture
	Publish  func(captureShareFixture)
	Refresh  func()
}

func maximumPolicyShareActors(t *testing.T) (identity.Principal, []string, []authorization.ShareRecipient) {
	t.Helper()
	opaque := func(length int) string {
		t.Helper()
		raw := make([]byte, (length*3+3)/4)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)[:length]
	}
	prefix := "https://id.example.test/"
	creator := identity.Principal{Issuer: prefix + opaque(2048-len(prefix)), Subject: opaque(256), ClientID: opaque(256), Kind: identity.Human}
	groups := make([]string, 8)
	recipients := make([]authorization.ShareRecipient, 8)
	for n := range groups {
		groups[n] = opaque(256)
		recipients[n] = authorization.ShareRecipient{Kind: "Group", Issuer: creator.Issuer, ID: opaque(256)}
	}
	slices.Sort(groups)
	slices.SortFunc(recipients, func(a, b authorization.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	if !creator.Valid() || len(creator.Issuer) != 2048 || !identity.Strings(groups, 8, 256) {
		t.Fatal("maximum-width actor shape")
	}
	return creator, groups, recipients
}

func newPolicyPaidShareService(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, objects *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, catalog *postgres.ContextPublications) (paidShareService, *pgxpool.Pool) {
	t.Helper()
	role := narrowRole(t, ctx, admin, "policy_share_hub_", "synthetic-policy-share-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("compiled sharing role")
		}
		return grants
	})
	pool := poolFor(role, "synthetic-policy-share-hub")
	t.Cleanup(pool.Close)
	ledger, err := postgres.NewEvidenceShares(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := postgres.NewContextCaseReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	service := paidShareService{Service: sharing.Service{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: catalog, Store: ledger, Policies: ledger, Recovery: s.recovery.reader, NewID: custodyID, Now: time.Now}, audit: newShareBusinessAudit(t, ctx, pool, objects, keys, s)}
	return service, pool
}

type policyShareCostSample struct {
	WAL                                                                                     string
	Rows, Revoked, TupleBytes, MaxTupleBytes, HeapBytes, IndexBytes, ToastBytes, TotalBytes int64
}

func samplePolicyShareCost(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root string) policyShareCostSample {
	t.Helper()
	var s policyShareCostSample
	if err := admin.QueryRow(ctx, `SELECT pg_current_wal_insert_lsn()::text,count(*)::bigint,count(*) FILTER(WHERE revoked_at IS NOT NULL)::bigint,
 coalesce(sum(pg_column_size(r)),0)::bigint,coalesce(max(pg_column_size(r)),0)::bigint,
 pg_relation_size('public.evidence_share'),pg_indexes_size('public.evidence_share'),
 (SELECT pg_total_relation_size(reltoastrelid) FROM pg_class WHERE oid='public.evidence_share'::regclass),pg_total_relation_size('public.evidence_share')
 FROM evidence_share r WHERE root_id=$1`, root).Scan(&s.WAL, &s.Rows, &s.Revoked, &s.TupleBytes, &s.MaxTupleBytes, &s.HeapBytes, &s.IndexBytes, &s.ToastBytes, &s.TotalBytes); err != nil {
		t.Fatal("policy cost snapshot", err)
	}
	return s
}

func logPolicyShareCost(t *testing.T, ctx context.Context, admin *pgxpool.Pool, phase string, before, after policyShareCostSample) int64 {
	t.Helper()
	var wal int64
	if err := admin.QueryRow(ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, after.WAL, before.WAL).Scan(&wal); err != nil || wal < 0 {
		t.Fatal("policy cost WAL", err, wal)
	}
	t.Logf("UNQUALIFIED policy_cost phase=%s rows=%d revoked=%d tuple_bytes=%d max_tuple_bytes=%d whole_relation_heap=%d indexes=%d toast=%d total=%d heap_growth=%d index_growth=%d toast_growth=%d total_growth=%d whole_instance_wal_delta=%d; includes background noise/page images and aborted work; physical pages are whole-table observations, not per-slot attribution; no installed IAM/backup/max-Unicode qualification", phase, after.Rows, after.Revoked, after.TupleBytes, after.MaxTupleBytes, after.HeapBytes, after.IndexBytes, after.ToastBytes, after.TotalBytes, after.HeapBytes-before.HeapBytes, after.IndexBytes-before.IndexBytes, after.ToastBytes-before.ToastBytes, after.TotalBytes-before.TotalBytes, wal)
	return wal
}

func qualifyMaximumPolicyShareCost(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, objects *objectstore.Store, keys authorityTestKeys, f policyShareCostFixture) {
	t.Helper()
	root := f.Scenario.a.RootID
	baseline := samplePolicyShareCost(t, ctx, admin, root)
	if baseline.Rows != 0 {
		t.Fatal("isolated maximum-width cohort already has shares")
	}
	t.Log("policy_cost_stage=accept_original_maximum_width issuer_bytes=2048 manager_groups=8 manager_subject_bytes=256 recipients=8 recipient_id_bytes=256 capture_allocation_slots=112 accepted_executions=100; random printable fields resist compression; original basis UID widths retained")
	acceptance := f.Accept()
	f.Grant()
	t.Log("policy_cost_stage=first_genuine_wide_admission")
	firstAccepted := f.Admit()
	t.Log("policy_cost_stage=first_genuine_wide_pair_and_manifest")
	first := f.Prepare(firstAccepted, true)
	t.Log("policy_cost_stage=first_genuine_wide_publication")
	f.Publish(first)
	var valid bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(octet_length(creator_issuer)=2048 AND octet_length(creator_subject)=256 AND octet_length(creator_client)=256
 AND jsonb_array_length(management)=8 AND jsonb_array_length(recipients)=8
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(management)m WHERE octet_length(m->>'Issuer')<>2048 OR octet_length(m->>'SubjectID')<>256)
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(recipients)p WHERE octet_length(p->>'issuer')<>2048 OR octet_length(p->>'id')<>256))
 FROM evidence_share WHERE root_id=$1 AND policy_acceptance_id=$2`, root, acceptance).Scan(&valid); err != nil || !valid {
		t.Fatal("first maximum-width share was not genuinely materialized", err)
	}
	firstSample := samplePolicyShareCost(t, ctx, admin, root)
	logPolicyShareCost(t, ctx, admin, "first-wide-capture-through-published-share", baseline, firstSample)
	t.Log("policy_cost_stage=first_wide_succeeded_continue_to_100")
	for n := 1; n < 100; n++ {
		accepted := f.Admit()
		ready := f.Prepare(accepted, false)
		f.Publish(ready)
		if (n+1)%25 == 0 {
			t.Logf("policy_cost_stage=published_count count=%d", n+1)
		}
	}
	complete := samplePolicyShareCost(t, ctx, admin, root)
	if complete.Rows != 100 || complete.Revoked != 0 {
		t.Fatal("genuine 100-share source cohort", complete.Rows, complete.Revoked)
	}
	var captured, spent, executions int64
	if err := admin.QueryRow(ctx, `SELECT shares_spent,executions_spent,(SELECT count(*) FROM evidence_share s JOIN context_capture c ON c.intent_operation_id=s.creating_operation_id AND c.root_id=s.root_id WHERE s.root_id=$1 AND s.policy_acceptance_id=$2) FROM policy_acceptance WHERE root_id=$1 AND id=$2`, root, acceptance).Scan(&spent, &executions, &captured); err != nil || spent != 100 || executions != 100 || captured != 100 {
		t.Fatal("100 original paid capture associations", err, spent, executions, captured)
	}
	logPolicyShareCost(t, ctx, admin, "100-genuine-wide-capture-shares", baseline, complete)
	service, hub := newPolicyPaidShareService(t, ctx, admin, poolFor, objects, keys, f.Scenario, first.reader)
	current := func() identities.CurrentIdentity {
		t.Helper()
		f.Refresh()
		now := time.Now().UTC().Truncate(time.Microsecond)
		i := f.Scenario.a.Eligibility.VerifiedIdentity
		i.Principal = f.Creator
		i.Groups = f.Groups
		i.Scopes = []string{"evidence:read", authorization.ShareScope}
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-maximum-width", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	// Exercise rollback of the same current generated SQL business transaction.
	// This deliberately does not claim the outer service authority path ran for
	// the aborted effect; its acknowledged normal operation stays charged.
	rollbackIdentity := current()
	rollbackOp := service.audit.begin(ctx, rollbackIdentity, "revoke_share", "maximum-rollback")
	if _, err := admin.Exec(ctx, `CHECKPOINT`); err != nil {
		t.Fatal("owned full-page-image checkpoint", err)
	}
	rollbackBefore := samplePolicyShareCost(t, ctx, admin, root)
	tx, err := hub.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := custodydb.New(tx)
	var rootID, opID, target pgtype.UUID
	_ = rootID.Scan(root)
	_ = opID.Scan(rollbackOp.ID)
	_ = target.Scan(acceptance)
	effect, err := q.BeginShareEffect(ctx, custodydb.BeginShareEffectParams{RootID: rootID, OperationID: opID, Action: "revoke_share", Issuer: f.Creator.Issuer, Subject: f.Creator.Subject, Client: f.Creator.ClientID, Target: target})
	if err != nil || !effect.EffectAvailable {
		t.Fatal("rollback paid effect", err)
	}
	if _, err = q.LockPolicySharingAcceptance(ctx, custodydb.LockPolicySharingAcceptanceParams{RootID: rootID, ID: target}); err != nil {
		t.Fatal(err)
	}
	key := pgtype.Text{String: "maximum-rollback", Valid: true}
	if n, err := q.RevokePolicySharing(ctx, custodydb.RevokePolicySharingParams{RootID: rootID, ID: target, SharingRevokeKey: key}); err != nil || n != 1 {
		t.Fatal("rollback policy effect", err, n)
	}
	if rows, err := q.RevokePolicyShares(ctx, custodydb.RevokePolicySharesParams{RootID: rootID, PolicyAcceptanceID: target, RevokeKey: key, OperationID: opID}); err != nil || len(rows) != 100 {
		t.Fatal("rollback 100-share mutation", err, len(rows))
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	rolledBack := samplePolicyShareCost(t, ctx, admin, root)
	if rolledBack.Revoked != 0 || rolledBack.Rows != 100 {
		t.Fatal("rollback changed retained shares")
	}
	var untouched bool
	if err = admin.QueryRow(ctx, `SELECT sharing_revoked_at IS NULL AND (SELECT share_effect_target IS NULL FROM operation_audit_lifecycle WHERE operation_id=$2) FROM policy_acceptance WHERE id=$1`, acceptance, rollbackOp.ID).Scan(&untouched); err != nil || !untouched {
		t.Fatal("rollback retained policy/effect marker", err)
	}
	rollbackWAL := logPolicyShareCost(t, ctx, admin, "generated-100-revoke-explicit-rollback", rollbackBefore, rolledBack)
	service.audit.finish(ctx, rollbackOp, errors.New("explicit fixture rollback"))
	if _, err = admin.Exec(ctx, `CHECKPOINT`); err != nil {
		t.Fatal(err)
	}
	paidBefore := samplePolicyShareCost(t, ctx, admin, root)
	t.Log("policy_cost_stage=actual_paid_public_revoke_all")
	input := sharing.PolicyRevokeInput{AcceptanceID: acceptance, ExpectedRevision: 1, IdempotencyKey: "maximum-paid-revoke"}
	result, err := service.RevokePolicySharing(ctx, current(), input)
	if err != nil || result.Replay || result.Revoked != 100 {
		t.Fatal("actual paid 100-share revoke-all", err, result.Revoked, result.Replay)
	}
	paidAfter := samplePolicyShareCost(t, ctx, admin, root)
	if paidAfter.Rows != 100 || paidAfter.Revoked != 100 {
		t.Fatal("paid revoke did not preserve exactly 100 originals")
	}
	paidWAL := logPolicyShareCost(t, ctx, admin, "full-paid-100-revoke-including-Begin-Finish", paidBefore, paidAfter)
	beforeReplay := samplePolicyShareCost(t, ctx, admin, root)
	if replay, err := service.RevokePolicySharing(ctx, current(), input); err != nil || !replay.Replay || replay.Revoked != 100 {
		t.Fatal("paid business replay", err, replay.Revoked, replay.Replay)
	}
	afterReplay := samplePolicyShareCost(t, ctx, admin, root)
	if afterReplay.Revoked != 100 || afterReplay.Rows != 100 {
		t.Fatal("replay changed business rows")
	}
	logPolicyShareCost(t, ctx, admin, "paid-replay-new-normal-operation-no-business-effect", beforeReplay, afterReplay)
	bound := service.audit.policy.History.MaximumTransitionWALBytes
	t.Logf("policy_cost_stage=observed_budget_comparison original_fixture_transition_WAL=%d default_configured_transition_WAL=%d observed_full_paid_WAL=%d observed_rollback_WAL=%d; no universal physical-layout claim", bound, 256<<10, paidWAL, rollbackWAL)
	if paidWAL > bound || rollbackWAL > bound {
		t.Fatal("original fixture profile does not cover measured 100-share transaction", bound, paidWAL, rollbackWAL)
	}
}
