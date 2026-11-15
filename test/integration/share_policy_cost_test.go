package integration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pure structural boundary reproduction: every component is domain-valid,
// while the combined immutable record exceeds the existing SQL adapter cap.
// This manufactures no persisted identity, signature, receipt or qualification.
func policyShareAcceptanceSizeFixture(t *testing.T, issuerBytes int) capture.PolicyAcceptance {
	t.Helper()
	// Fix timestamp width so the encoded-size boundary is reproducible.
	now := time.Date(2026, time.November, 11, 12, 13, 14, 123456000, time.UTC)
	creator, groups, recipients := widePolicyShareActors(t, issuerBytes)
	root, installation, policyID, cluster, delegation := custodyID(), custodyID(), custodyID(), custodyID(), custodyID()
	revision := identity.Revision{UID: policyID, Generation: 1, Digest: artifact.Digest{1}}
	owners := make([]artifact.AudienceAssignment, 8)
	managers := make([]artifact.AudienceAssignment, 8)
	for n := range owners {
		owners[n] = artifact.AudienceAssignment{Kind: "Group", Issuer: creator.Issuer, SubjectID: groups[n], Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: delegation, AssignmentID: custodyID(), BasisDigest: artifact.Digest{byte(n + 1)}}
		managers[n] = owners[n]
		managers[n].Role = "evidence-owner"
		managers[n].AssignmentID = custodyID()
	}
	slices.SortFunc(managers, func(a, b artifact.AudienceAssignment) int { return strings.Compare(a.AssignmentID, b.AssignmentID) })
	source := capture.PolicySource{InstallationID: installation, ClusterID: cluster, NamespaceUID: "control", Name: "synthetic-maximum", Revision: revision, ResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(30 * time.Second), CollectionDigest: artifact.Digest{2}}
	authority := authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: policyID, Creator: creator, Executor: authorization.PolicyPrincipal(installation, policyID), ScopeDigest: artifact.Digest{3}, ClusterID: cluster, NamespaceUID: "app", WorkloadUID: "workload", Delegation: identity.Revision{UID: delegation, Generation: 1, Digest: artifact.Digest{4}}, Owners: owners, Actions: []string{authorization.PolicyContextAction}, Limits: authorization.AutomationLimits{MaxExecutions: 100, MaxBytes: 1 << 20}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
	submission := capture.VerifiedPolicySubmission{Nonce: custodyID(), Actor: creator, Source: revision, ClusterID: cluster, NamespaceUID: "control", Name: source.Name, ScopeDigest: authority.ScopeDigest, EnvelopeDigest: artifact.Digest{5}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
	record := capture.PolicyAcceptance{ID: custodyID(), RootID: root, Source: source, Submission: submission, Authority: authority, Submitter: creator, IdentityRevision: identity.Revision{UID: "synthetic-identity", Generation: 1, Digest: artifact.Digest{7}}, PermissionRevision: identity.Revision{UID: root, Generation: 1, Digest: artifact.Digest{8}}, IntentVersion: 1, AcceptedAt: now, Sharing: &capture.PolicyShareInstruction{Creator: creator, Management: managers, Recipients: recipients, MaxCaptures: 100, NotAfter: now.Add(time.Hour).Truncate(time.Second)}}
	if !record.Valid() {
		t.Fatal("individual maximum components are not domain valid", authority.Valid(now), record.Sharing.Valid(), source.Valid(now))
	}
	return record
}

func TestPolicyShareAcceptanceRecordSizeBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		issuerBytes int
		rejected    bool
	}{{"all-individual-maxima-rejected", 2048, true}, {"wide-sample-below-cap", policyWideSampleIssuerBytes, false}} {
		t.Run(tc.name, func(t *testing.T) {
			record := policyShareAcceptanceSizeFixture(t, tc.issuerBytes)
			body, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			authorityBody, _ := json.Marshal(record.Authority)
			sharingBody, _ := json.Marshal(record.Sharing)
			t.Logf("domain_valid_record=true issuer_bytes=%d encoded_record_bytes=%d closed_adapter_limit=%d authority_bytes=%d sharing_bytes=%d structurally_rejected=%t; no database admission or physical-budget claim", tc.issuerBytes, len(body), 64<<10, len(authorityBody), len(sharingBody), len(body) > 64<<10)
			if (len(body) > 64<<10) != tc.rejected {
				t.Fatal("aggregate boundary changed", len(body), tc.rejected)
			}
		})
	}
}

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

func shareFixtureFailureStage(err error) string {
	var fixed interface{ FixedStep() string }
	if errors.As(err, &fixed) {
		return fixed.FixedStep()
	}
	return "unclassified"
}

// Mirror the existing API-work producer predicates as read-only diagnostics:
// no scope, state, receipt or cutoff is rewritten by this assertion.
func assertPolicyAPIWorkSource(t *testing.T, ctx context.Context, admin *pgxpool.Pool, c capture.Accepted, acknowledged bool) {
	t.Helper()
	var state string
	var hasAck, paired, namespace, workload, unboundNode bool
	if err := admin.QueryRow(ctx, `SELECT state,intent_acknowledged_at IS NOT NULL,intent_operation_id=id,
 convert_from(scope_json,'UTF8')::jsonb#>>'{collection,spec,target,namespace}'=$2,
 convert_from(scope_json,'UTF8')::jsonb#>>'{collection,spec,target,workloadRef,uid}'=$3,
 coalesce(convert_from(pod_pin_json,'UTF8')::jsonb->>'NodeName','')=''
 FROM context_capture WHERE id=$1`, c.CaptureID, c.Expectation.Namespace, c.Expectation.WorkloadUID).Scan(&state, &hasAck, &paired, &namespace, &workload, &unboundNode); err != nil {
		t.Fatal("API work source diagnostics", err)
	}
	t.Logf("policy_api_source state=%s acknowledged=%t private_pair=%t exact_namespace=%t exact_workload=%t node_unbound=%t", state, hasAck, paired, namespace, workload, unboundNode)
	if hasAck != acknowledged || !paired || !namespace || !workload || !unboundNode || acknowledged && state != capture.IntentAudited {
		t.Fatal("prepaid API source violates original producer predicates")
	}
}

const policyWideSampleIssuerBytes = 1536

// Fixed before authority or audience acceptance. This is a wide admitted sample,
// not simultaneous individual maxima or a universal physical qualification.
func widePolicyShareActors(t *testing.T, issuerBytes int) (identity.Principal, []string, []authorization.ShareRecipient) {
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
	creator := identity.Principal{Issuer: prefix + opaque(issuerBytes-len(prefix)), Subject: opaque(256), ClientID: opaque(256), Kind: identity.Human}
	groups := make([]string, 8)
	recipients := make([]authorization.ShareRecipient, 8)
	for n := range groups {
		groups[n] = opaque(256)
		recipients[n] = authorization.ShareRecipient{Kind: "Group", Issuer: creator.Issuer, ID: opaque(256)}
	}
	slices.Sort(groups)
	slices.SortFunc(recipients, func(a, b authorization.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	if !creator.Valid() || len(creator.Issuer) != issuerBytes || !identity.Strings(groups, 8, 256) {
		t.Fatal("wide actor shape")
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
	ledger, err := postgres.NewEvidenceShares(ctx, pool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := postgres.NewContextCaseReads(ctx, pool, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	service := paidShareService{Service: sharing.Service{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: catalog, Store: ledger, Policies: ledger, NewID: custodyID, Now: time.Now}}
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
 FROM evidence_share r WHERE r.root_id=$1`, root).Scan(&s.WAL, &s.Rows, &s.Revoked, &s.TupleBytes, &s.MaxTupleBytes, &s.HeapBytes, &s.IndexBytes, &s.ToastBytes, &s.TotalBytes); err != nil {
		t.Fatal("policy cost snapshot", err)
	}
	return s
}

func logPolicyShareCost(t *testing.T, ctx context.Context, admin *pgxpool.Pool, phase string, before, after policyShareCostSample) {
	t.Helper()
	var wal int64
	if err := admin.QueryRow(ctx, `SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint`, after.WAL, before.WAL).Scan(&wal); err != nil || wal < 0 {
		t.Fatal("policy cost WAL", err, wal)
	}
	t.Logf("UNQUALIFIED policy_cost phase=%s rows=%d revoked=%d tuple_bytes=%d max_tuple_bytes=%d heap=%d indexes=%d toast=%d total=%d whole_instance_wal_delta=%d; includes background noise", phase, after.Rows, after.Revoked, after.TupleBytes, after.MaxTupleBytes, after.HeapBytes, after.IndexBytes, after.ToastBytes, after.TotalBytes, wal)
}

func qualifyWidePolicyShareCost(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, objects *objectstore.Store, keys authorityTestKeys, f policyShareCostFixture) {
	t.Helper()
	root := f.Scenario.a.RootID
	baseline := samplePolicyShareCost(t, ctx, admin, root)
	if baseline.Rows != 0 {
		t.Fatal("isolated wide-sample cohort already has shares")
	}
	acceptance := f.Accept()
	f.Grant()
	first := f.Prepare(f.Admit(), true)
	f.Publish(first)
	var valid bool
	if err := admin.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(octet_length(creator_issuer)=$3 AND octet_length(creator_subject)=256 AND octet_length(creator_client)=256
 AND jsonb_array_length(management)=8 AND jsonb_array_length(recipients)=8
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(management)m WHERE octet_length(m->>'Issuer')<>$3 OR octet_length(m->>'SubjectID')<>256)
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(recipients)p WHERE octet_length(p->>'issuer')<>$3 OR octet_length(p->>'id')<>256))
 FROM evidence_share WHERE root_id=$1 AND policy_acceptance_id=$2`, root, acceptance, policyWideSampleIssuerBytes).Scan(&valid); err != nil || !valid {
		t.Fatal("first wide-sample share was not genuinely materialized", err)
	}
	logPolicyShareCost(t, ctx, admin, "first-wide-capture-through-published-share", baseline, samplePolicyShareCost(t, ctx, admin, root))
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
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	if _, err := current().ResolveIdentity(ctx); err != nil {
		t.Fatal("wide-sample caller preflight", err)
	}
	for n := 1; n < 100; n++ {
		f.Publish(f.Prepare(f.Admit(), false))
		if (n+1)%25 == 0 {
			t.Logf("policy_cost_stage=published_count count=%d", n+1)
		}
	}
	complete := samplePolicyShareCost(t, ctx, admin, root)
	if complete.Rows != 100 || complete.Revoked != 0 {
		t.Fatal("genuine 100-share source cohort", complete.Rows, complete.Revoked)
	}
	var spent, executions, audited int64
	if err := admin.QueryRow(ctx, `SELECT shares_spent,executions_spent,(SELECT count(*) FROM audit_event e JOIN evidence_share s ON s.id::text=ANY(e.share_ids) WHERE e.kind='share.create' AND s.root_id=$1 AND s.policy_acceptance_id=$2) FROM policy_acceptance WHERE root_id=$1 AND id=$2`, root, acceptance).Scan(&spent, &executions, &audited); err != nil || spent != 100 || executions != 100 || audited != 100 {
		t.Fatal("100 policy shares, each with its publication audit row", err, spent, executions, audited)
	}
	logPolicyShareCost(t, ctx, admin, "100-genuine-wide-capture-shares", baseline, complete)
	// The real hub role can update both management and revocation; a
	// revocation that also changes management fails its branch guard.
	_, err := hub.Exec(ctx, `UPDATE evidence_share SET revoked_at=clock_timestamp(),revoke_key='branch-probe',revision=revision+1,management=jsonb_build_array(management->0)
 WHERE root_id=$1 AND id=(SELECT id FROM evidence_share WHERE root_id=$1 AND policy_acceptance_id=$2
 AND revoked_at IS NULL AND jsonb_array_length(management)=8 ORDER BY id LIMIT 1)`, root, acceptance)
	var refusal *pgconn.PgError
	if !errors.As(err, &refusal) || refusal.Code != "23514" || refusal.Message != "share revocation changes only the revocation" {
		t.Fatal("revocation changed management or failed outside its branch guard", err)
	}
	before := samplePolicyShareCost(t, ctx, admin, root)
	input := sharing.PolicyRevokeInput{AcceptanceID: acceptance, ExpectedRevision: 1, IdempotencyKey: "wide-sample-revoke"}
	result, err := service.RevokePolicySharing(ctx, current(), input)
	if err != nil || result.Replay || result.Revoked != 100 {
		t.Fatal("100-share revoke-all", err, result.Revoked, result.Replay)
	}
	after := samplePolicyShareCost(t, ctx, admin, root)
	if after.Rows != 100 || after.Revoked != 100 {
		t.Fatal("revoke-all did not preserve exactly 100 originals")
	}
	var revokeRows int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind='share.revoke' AND operation='revoke_share' AND cardinality(share_ids)=100 AND subject=$1`, f.Creator.Subject).Scan(&revokeRows); err != nil || revokeRows != 1 {
		t.Fatal("revoke-all wrote one audit row naming its 100 shares", err, revokeRows)
	}
	logPolicyShareCost(t, ctx, admin, "100-revoke-all", before, after)
	if replay, err := service.RevokePolicySharing(ctx, current(), input); err != nil || !replay.Replay || replay.Revoked != 100 {
		t.Fatal("business replay", err, replay.Revoked, replay.Replay)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE kind='share.revoke' AND subject=$1`, f.Creator.Subject).Scan(&revokeRows); err != nil || revokeRows != 1 {
		t.Fatal("a replay wrote another effect row", err, revokeRows)
	}
}
