package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyPolicyShare (ADR-239) runs bounded recurring-policy sharing through
// real PostgreSQL: genuine policy acceptances (source observation, SQL
// acceptance with the instruction, acknowledged encrypted audit) and genuine
// policy-executor admissions of one workload. Each admitted capture claims a
// slot of its acceptance in the admission transaction; the (maxCaptures+1)th
// capture is unshared, a new admission adapter (a restarted hub) continues the
// stored counter, a newer DebugPolicy generation stops sharing and a new
// acceptance never backfills, a capture published after notAfter is unshared,
// and revoke-all revokes exactly its acceptance's shares and stops its
// pending captures from being shared.
func qualifyPolicyShare(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T, int64) captureAdmissionScenario, prepare func(*testing.T, captureAdmissionScenario, capture.Accepted, bool) captureShareFixture) {
	t.Helper()
	s := create(t, 12)
	root, installation := s.a.RootID, s.recovery.installation
	pod := s.a.Plan.Input.Target.Target()
	workload := authorization.WorkloadScope(pod.ClusterID, pod.NamespaceUID, pod.WorkloadUID)
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	publishAuthority := func() {
		t.Helper()
		for range 2 {
			if err := (auditapp.AuthorityPublisher{Ledger: s.p, Objects: &objectstore.AuthorityObjects{Store: store, Seal: keys, Open: keys}}).PublishAuthority(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	refresh := func() {
		t.Helper()
		b := s.batch
		b.Initial = nil
		b.ObservedAt = clock()
		b.FreshUntil = b.ObservedAt.Add(5 * time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
	}

	// The maintainers' AccessBinding becomes the team's automation binding and
	// holds evidence-owner too: the policy's owner team (ADR-239).
	b := &s.batch.Bases[0]
	b.Roles = []string{"workload-maintainer", "evidence-owner"}
	b.Automation = &authorization.AutomationEnvelope{AllowedActions: []string{authorization.PolicyContextAction}, MaxLifetimeSeconds: 3600, MaxExecutions: 100, MaxBytes: 1 << 30}
	b.Resource.Generation++
	b.Resource.SpecDigest[0]++
	b.Resource.ResourceVersion = custodyID()
	b.Continuous = true
	b.ScopeDigest = configapp.PermissionScopeDigest(*b)
	s.batch.RequestID, s.batch.ObservedAt = custodyID(), clock()
	s.batch.FreshUntil = s.batch.ObservedAt.Add(5 * time.Second)
	s.batch.InputDigest[0]++
	accepted, err := s.p.AcceptPermissions(ctx, s.batch)
	if err != nil {
		t.Fatal("automation binding", err)
	}
	s.batch.ExpectedSequence = accepted.Sequence
	publishAuthority()
	projection, err := s.p.Permissions(ctx, workload)
	if err != nil {
		t.Fatal(err)
	}
	var sponsor, owner artifact.AudienceAssignment
	for _, a := range projection.Allows {
		if a.Audience.BasisUID == b.Resource.UID && a.Audience.Role == "workload-maintainer" {
			sponsor = a.Audience
		}
		if a.Audience.BasisUID == b.Resource.UID && a.Audience.Role == "evidence-owner" {
			owner = a.Audience
		}
	}
	if sponsor.AssignmentID == "" || owner.AssignmentID == "" {
		t.Fatal("automation binding assignments", projection.Allows)
	}

	factory := func(role, password string) *postgres.Policies {
		pool := poolFor(role, password)
		t.Cleanup(pool.Close)
		r, err := postgres.NewPolicies(ctx, pool, root, installation)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	sources, acceptor, auditor, reader := factory("policy_source_runtime", "synthetic-policy-source"), factory("policy_accept_runtime", "synthetic-policy-accept"), factory("policy_audit_runtime", "synthetic-policy-audit"), factory("policy_read_runtime", "synthetic-policy-read")
	readPool := poolFor("policy_read_runtime", "synthetic-policy-read")
	t.Cleanup(readPool.Close)
	automation, err := postgres.NewAutomationAuthorities(ctx, readPool, root, installation)
	if err != nil {
		t.Fatal(err)
	}
	policyUID := custodyID()
	creator := s.a.Eligibility.VerifiedIdentity.Principal
	recipient := authorization.ShareRecipient{Kind: "User", Issuer: creator.Issuer, ID: "synthetic-policy-recipient"}
	source := capture.PolicySource{InstallationID: installation, ClusterID: custodyID(), NamespaceUID: "control", Name: "restarts", Revision: identity.Revision{UID: policyUID, Generation: 1, Digest: artifact.Digest{51}}, ResourceVersion: "policy-1", CollectionDigest: artifact.Digest{52}}
	observe := func() {
		t.Helper()
		source.ObservedAt = clock()
		source.FreshUntil = source.ObservedAt.Add(30 * time.Second)
		source.ResourceVersion = custodyID()
		if err := sources.ObservePolicy(ctx, source); err != nil {
			t.Fatal("observe policy", err)
		}
	}
	// accept activates the current source revision with recurring sharing, as
	// the activation does after its checks, and acknowledges its audit.
	var active string
	var authority authorization.AcceptedPolicyAuthority
	accept := func(scope byte, maxCaptures int, notAfter time.Time) string {
		t.Helper()
		refresh()
		observe()
		now := clock()
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		authority = authorization.AcceptedPolicyAuthority{InstallationID: installation, PolicyUID: policyUID, Creator: creator, Executor: authorization.PolicyPrincipal(installation, policyUID), ScopeDigest: artifact.Digest{scope}, ClusterID: pod.ClusterID, NamespaceUID: pod.NamespaceUID, WorkloadUID: pod.WorkloadUID,
			Delegation: identity.Revision{UID: b.Resource.UID, Generation: b.Resource.Generation, Digest: b.Resource.SpecDigest}, Owners: []artifact.AudienceAssignment{sponsor}, Actions: []string{authorization.PolicyContextAction}, Limits: authorization.AutomationLimits{MaxExecutions: 50, MaxBytes: 1 << 20}, IssuedAt: now, NotAfter: now.Add(time.Hour)}
		author := identity.Identity{Principal: creator, Scopes: []string{"evidence:read", "evidence:capture", authorization.ShareScope}, Groups: []string{"maintainers"}, Policy: s.a.Eligibility.VerifiedIdentity.Policy, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
		in := capture.PolicyAdmission{RootID: root, Recovery: recovery, Target: workload, Authority: authority, Author: author,
			Submission: capture.VerifiedPolicySubmission{ReplacesID: active, Nonce: custodyID(), Actor: creator, Source: source.Revision, ClusterID: source.ClusterID, NamespaceUID: source.NamespaceUID, Name: source.Name, ScopeDigest: authority.ScopeDigest, EnvelopeDigest: artifact.Digest{53}, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)},
			Sharing:    &capture.PolicyShareInstruction{Creator: creator, Management: []artifact.AudienceAssignment{owner}, Recipients: []authorization.ShareRecipient{recipient}, MaxCaptures: maxCaptures, NotAfter: notAfter.UTC().Truncate(time.Second)}}
		in.Verification = syntheticSubmissionCheck(in, now)
		r, err := acceptor.AcceptPolicy(ctx, in)
		if err != nil {
			t.Fatal("accept policy with sharing", err)
		}
		if err = (auditapp.PolicyAcceptancePublisher{Ledger: auditor, Objects: &objectstore.PolicyAcceptanceObjects{Store: store, Seal: keys, Open: keys}}).PublishPolicyAcceptances(ctx); err != nil {
			t.Fatal(err)
		}
		if r.Record.Sharing == nil || r.Record.Sharing.MaxCaptures != maxCaptures {
			t.Fatal("acceptance record lost its sharing instruction", r.Record.Sharing)
		}
		active = r.Record.ID
		return active
	}
	// admit admits one policy-executor capture of the triggering Pod through
	// the given admission adapter, with every current check.
	admitInput := func() capture.Admission {
		t.Helper()
		refresh()
		observe()
		now := clock()
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		current, err := automation.PolicyAutomationAuthority(ctx, authority, pod)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot, err := reader.AcceptedPolicyAuthority(ctx, policyUID); err != nil || snapshot.Authority.ScopeDigest != authority.ScopeDigest {
			t.Fatal("current acceptance unavailable to the policy executor", err)
		}
		executor := authorization.PolicyExecutorIdentity(authority, now, now.Add(20*time.Second))
		eligibility := authorization.PolicyContextEligibility(executor, authority, current, pod, now)
		if !eligibility.Eligible {
			t.Fatal("policy executor not eligible", eligibility.Reason)
		}
		a := s.a
		in := a.Plan.Input
		in.CaptureID, in.Executor = custodyID(), executor.Principal
		in.Deadline = now.Add(time.Minute)
		// The test spans minutes: renew the scenario's synthetic Pod, capability,
		// retention and storage-binding observations as the hub's readers would.
		in.Target.ObservedAt, in.Target.FreshUntil = now, now.Add(5*time.Second)
		in.Capability.ObservedAt, in.Capability.FreshUntil = now, now.Add(30*time.Second)
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		in.Retention.Proof, in.Retention.ValidUntil = policies.Proof, policies.FreshUntil
		a.Storage.ObservedAt, a.Storage.FreshUntil = now, now.Add(30*time.Second)
		if _, err = admin.Exec(ctx, "UPDATE context_storage_binding SET observed_at=$2,fresh_until=$3 WHERE root_id=$1", root, a.Storage.ObservedAt, a.Storage.FreshUntil); err != nil {
			t.Fatal(err)
		}
		plan, err := planning.CompileContext(in, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// Fixture only: model Tick's already-spent original occurrence. Product
		// Tick performs these under its source lock; admission must not debit
		// accepted execution a second time.
		key := custodyID()
		if _, err = admin.Exec(ctx, `UPDATE policy_acceptance SET executions_spent=executions_spent+1 WHERE id=$1`, active); err != nil {
			t.Fatal(err)
		}
		if _, err = admin.Exec(ctx, `INSERT INTO policy_occurrence(id,root_id,policy_uid,acceptance_id,cluster_id,workload_uid,pod_uid,restarts) SELECT $1,$2,$3,$4,$5,$6,$7,executions_spent FROM policy_acceptance WHERE id=$4`, key, root, policyUID, active, pod.ClusterID, pod.WorkloadUID, pod.PodUID); err != nil {
			t.Fatal(err)
		}
		a.Plan, a.Eligibility, a.Recovery, a.IdempotencyKey = plan, eligibility, recovery, key
		a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = custodyID(), custodyID()
		a.Registration.WriteUntil = in.Deadline
		a.CaseID, a.OccurrenceID = custodyID(), custodyID()
		return a
	}
	admit := func(admissions *postgres.ContextAdmissions) capture.Accepted {
		t.Helper()
		a := admitInput()
		got, err := admissions.AdmitContext(ctx, a)
		if err != nil {
			use := authorization.PolicyUse{PolicyUID: authority.PolicyUID, ScopeDigest: authority.ScopeDigest, Target: pod, Purpose: authorization.PolicyIncident}
			e := (authapp.AutomationEvaluator{Accepted: reader, Current: automation, Now: time.Now}).Eligibility(ctx, use)
			t.Fatalf("policy capture admission: %v (evaluator %s, eligible until %s, now %s)", err, e.Reason, a.Eligibility.ValidUntil, time.Now())
		}
		// A replayed admission (a lost reply) returns the same capture and
		// claims no second slot.
		if again, err := admissions.AdmitContext(ctx, a); err != nil || again.CaptureID != got.CaptureID {
			t.Fatal("policy capture replay", again.CaptureID, err)
		}
		var executions, output, reservations int64
		if err := admin.QueryRow(ctx, `SELECT executions_spent,collected_bytes_spent,(SELECT count(*) FROM policy_occurrence WHERE acceptance_id=$1 AND reserved_capture_id IS NOT NULL) FROM policy_acceptance WHERE id=$1`, active).Scan(&executions, &output, &reservations); err != nil || output != reservations*artifact.MaxContextBytes || executions != reservations {
			t.Fatal("capture/replay doubled execution or changed conservative output", executions, output, reservations, err)
		}
		return got
	}
	type instruction struct {
		ShareID    string `json:"share_id"`
		Acceptance string `json:"policy_acceptance_id"`
	}
	stored := func(c capture.Accepted) *instruction {
		t.Helper()
		var raw *string
		if err := admin.QueryRow(ctx, "SELECT share_instruction::text FROM context_capture WHERE id=$1", c.CaptureID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if raw == nil {
			return nil
		}
		var w instruction
		if json.Unmarshal([]byte(*raw), &w) != nil || !authorization.UUID(w.ShareID) || !authorization.UUID(w.Acceptance) {
			t.Fatal("malformed policy share instruction", *raw)
		}
		return &w
	}
	spent := func(acceptance string) int {
		t.Helper()
		var n int
		if err := admin.QueryRow(ctx, "SELECT shares_spent FROM policy_acceptance WHERE id=$1", acceptance).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	type shareRow struct {
		ID, Acceptance string
		Revoked        bool
	}
	shares := func() map[string]shareRow {
		t.Helper()
		rows, err := admin.Query(ctx, "SELECT id::text,COALESCE(policy_acceptance_id::text,''),revoked_at IS NOT NULL,idempotency_key FROM evidence_share WHERE root_id=$1", root)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]shareRow{}
		for rows.Next() {
			var r shareRow
			var key string
			if err = rows.Scan(&r.ID, &r.Acceptance, &r.Revoked, &key); err != nil {
				t.Fatal(err)
			}
			out[key] = r
		}
		return out
	}
	publish := func(f captureShareFixture) {
		t.Helper()
		refresh()
		if _, err := f.publish(); err != nil {
			t.Fatal("publication", err)
		}
	}
	// The hub's actual capture-admit grants (ADR-228 policy reads); each call
	// is a new adapter and pool, as after a hub restart.
	// narrowRole names one role per prefix and database.
	captureAdmissions := func(prefix string) *postgres.ContextAdmissions {
		t.Helper()
		role := narrowRole(t, ctx, admin, prefix, "synthetic-policy-share-admit", func(role string) []string {
			grants, ok := postgres.PublicRuntimeRoleGrantSQL("capture-admit", role)
			if !ok {
				t.Fatal("missing compiled capture-admit grants")
			}
			return grants
		})
		pool := poolFor(role, "synthetic-policy-share-admit")
		t.Cleanup(pool.Close)
		a, err := postgres.NewContextAdmissions(ctx, pool, root, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	// Acceptance A of generation 1 shares at most three captures.
	first := accept(61, 3, time.Now().Add(time.Hour))
	firstGrant := attachPolicyAccountingGrant(t, ctx, admin, poolFor, s, authority)
	hub := captureAdmissions("policy_share_admit_a_")
	c1, c2 := admit(hub), admit(hub)
	// A restarted hub (a new admission adapter) continues the stored counter.
	restarted := captureAdmissions("policy_share_admit_b_")
	c3, c4 := admit(restarted), admit(restarted)
	// The same original grant/acceptance pools survive a new adapter and lost
	// admission replies. A fifth occurrence stays pre-spent, but its refused
	// capture adds neither grant nor output spend and creates no reservation.
	refused := admitInput()
	if _, err := restarted.AdmitContext(ctx, refused); !errors.Is(err, capture.ErrCapacity) {
		t.Fatal("exhausted attached grant admitted a fifth capture", err)
	}
	var grantExecutions, grantBytes, acceptedExecutions, acceptedBytes int64
	if err := admin.QueryRow(ctx, `SELECT policy_executions_spent,policy_bytes_spent FROM access_grant WHERE id=$1`, firstGrant).Scan(&grantExecutions, &grantBytes); err != nil || grantExecutions != 4 || grantBytes != 4*artifact.MaxContextBytes {
		t.Fatal("grant replay/restart/refusal refilled or overspent", grantExecutions, grantBytes, err)
	}
	if err := admin.QueryRow(ctx, `SELECT executions_spent,collected_bytes_spent FROM policy_acceptance WHERE id=$1`, first).Scan(&acceptedExecutions, &acceptedBytes); err != nil || acceptedExecutions != 5 || acceptedBytes != 4*artifact.MaxContextBytes {
		t.Fatal("accepted execution double-debit or output refund", acceptedExecutions, acceptedBytes, err)
	}
	var reserved bool
	if err := admin.QueryRow(ctx, `SELECT reserved_capture_id IS NOT NULL FROM policy_occurrence WHERE id=$1`, refused.IdempotencyKey).Scan(&reserved); err != nil || reserved {
		t.Fatal("refused capture retained a new output reservation", err)
	}
	for _, c := range []capture.Accepted{c1, c2, c3} {
		if w := stored(c); w == nil || w.Acceptance != first {
			t.Fatal("capture within the limit is unshared", c.CaptureID, w)
		}
	}
	if w := stored(c4); w != nil {
		t.Fatal("the (maxCaptures+1)th capture claimed a sharing slot", w)
	}
	if n := spent(first); n != 3 {
		t.Fatal("restart or replay changed the counter", n)
	}
	f1, f2 := prepare(t, s, c1, true), prepare(t, s, c2, false)
	publish(f1)
	publish(f2)
	got := shares()
	if len(got) != 2 || got["capture:"+c1.CaptureID].Acceptance != first || got["capture:"+c2.CaptureID].Acceptance != first || got["capture:"+c1.CaptureID].ID != stored(c1).ShareID {
		t.Fatal("published policy captures were not shared under their acceptance", got)
	}

	// Editing the DebugPolicy (generation 2) stops sharing: acceptance B of the
	// new revision starts its own counter, and nothing earlier is backfilled.
	source.Revision.Generation, source.Revision.Digest = 2, artifact.Digest{54}
	observe()
	second := accept(62, 3, time.Now().Add(25*time.Second))
	c5, c6 := admit(hub), admit(hub)
	if w := stored(c5); w == nil || w.Acceptance != second {
		t.Fatal("new revision does not share", w)
	}
	if w := stored(c4); w != nil || spent(first) != 3 || spent(second) != 2 {
		t.Fatal("new acceptance backfilled or reset an earlier counter", w, spent(first), spent(second))
	}
	f5, f6 := prepare(t, s, c5, false), prepare(t, s, c6, false)
	publish(f5)
	// Generation 3 is not activated: B stops sharing although under its limit.
	source.Revision.Generation, source.Revision.Digest = 3, artifact.Digest{55}
	observe()
	if c7 := admit(hub); stored(c7) != nil || spent(second) != 2 {
		t.Fatal("an edited policy kept sharing", stored(c7), spent(second))
	}
	// A capture admitted before notAfter but published after it is unshared.
	var end time.Time
	if err = admin.QueryRow(ctx, "SELECT (record#>>'{Sharing,NotAfter}')::timestamptz FROM policy_acceptance WHERE id=$1", second).Scan(&end); err != nil {
		t.Fatal(err)
	}
	// The scenario's synthetic recovery observation lives 30 seconds, which
	// this wait (about 25 seconds) would otherwise cross for the publications
	// below. Renew it as its producer would, once before and once after.
	renewRecovery := func() {
		t.Helper()
		if err := renewSyntheticFleetObservation(ctx, admin, s.recovery.observation, 30*time.Second, true); err != nil {
			t.Fatal("renew synthetic recovery observation", err)
		}
	}
	renewRecovery()
	time.Sleep(time.Until(end) + time.Second)
	renewRecovery()
	publish(f6)
	if _, exists := shares()["capture:"+c6.CaptureID]; exists {
		t.Fatal("a capture published after notAfter was shared")
	}
	if r := shares()["capture:"+c5.CaptureID]; r.Acceptance != second || r.Revoked {
		t.Fatal("capture published before notAfter is not shared", r)
	}

	// Revoke-all of A revokes exactly A's shares, through the hub's own grants.
	hubRole := narrowRole(t, ctx, admin, "policy_share_hub_", "synthetic-policy-share-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing compiled hub grants")
		}
		return grants
	})
	hubPool := poolFor(hubRole, "synthetic-policy-share-hub")
	t.Cleanup(hubPool.Close)
	ledger, err := postgres.NewEvidenceShares(ctx, hubPool, root, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := postgres.NewContextCaseReads(ctx, hubPool, root, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	service := sharing.Service{RootID: root, InstallationID: installation, Routes: routes, Permissions: s.p, Catalog: f1.reader, Store: ledger, Policies: ledger, Recovery: s.recovery.reader, NewID: custodyID, Now: time.Now}
	as := func(subject string, groups []string) identities.CurrentIdentity {
		t.Helper()
		refresh()
		now := clock()
		i := identity.Identity{Principal: creator, Scopes: []string{"evidence:read", authorization.ShareScope}, Groups: groups, Policy: s.a.Eligibility.VerifiedIdentity.Policy, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
		i.Principal.Subject = subject
		current, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return current
	}
	if _, err := service.RevokePolicySharing(ctx, as("synthetic-policy-recipient", nil), first, 1, "revoke-all"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("a recipient revoked the policy's sharing", err)
	}
	// A current owner-team member (not the creator) manages the sharing.
	r, err := service.RevokePolicySharing(ctx, as("synthetic-team-mate", []string{"maintainers"}), first, 1, "revoke-all")
	if err != nil || r.Revoked != 2 || r.Replay {
		t.Fatal("revoke-all", r, err)
	}
	if again, err := service.RevokePolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), first, 1, "revoke-all"); err != nil || !again.Replay || again.Revoked != 2 {
		t.Fatal("revoke-all replay", again, err)
	}
	// A replay with a stale expected revision cannot report a revision the
	// store never produced.
	if _, err := service.RevokePolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), first, 2, "revoke-all"); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("replay with another expected revision", err)
	}
	if _, err := service.RevokePolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), first, 1, "another-key"); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("second revoke-all under another key", err)
	}
	got = shares()
	if !got["capture:"+c1.CaptureID].Revoked || !got["capture:"+c2.CaptureID].Revoked || got["capture:"+c5.CaptureID].Revoked {
		t.Fatal("revoke-all did not revoke exactly its acceptance's shares", got)
	}
	// Stop future sharing (REQ-SHR-007) of acceptance C (generation 3): a
	// current team member stops it; the capture that claimed its slot before
	// the Stop still publishes its share, the next capture claims none, and
	// revoke-all at revision 2 then revokes that share.
	third := accept(63, 3, time.Now().Add(time.Hour))
	c8 := admit(hub)
	if w := stored(c8); w == nil || w.Acceptance != third {
		t.Fatal("acceptance C does not share", w)
	}
	if _, err := service.StopPolicySharing(ctx, as("synthetic-policy-recipient", nil), third, 1, "stop"); !errors.Is(err, capture.ErrDenied) {
		t.Fatal("a recipient stopped the policy's sharing", err)
	}
	if r, err := service.StopPolicySharing(ctx, as("synthetic-team-mate", []string{"maintainers"}), third, 1, "stop"); err != nil || r.Replay {
		t.Fatal("stop future sharing", r, err)
	}
	if r, err := service.StopPolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), third, 1, "stop"); err != nil || !r.Replay {
		t.Fatal("stop replay", r, err)
	}
	if _, err := service.StopPolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), third, 1, "stop-again"); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("second stop under another key", err)
	}
	if c9 := admit(hub); stored(c9) != nil || spent(third) != 1 {
		t.Fatal("a stopped sharing claimed a slot", stored(c9), spent(third))
	}
	f8 := prepare(t, s, c8, false)
	publish(f8)
	if r := shares()["capture:"+c8.CaptureID]; r.Acceptance != third || r.Revoked {
		t.Fatal("a capture claimed before the Stop did not publish its share", r)
	}
	if _, err := service.RevokePolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), third, 1, "revoke-third"); !errors.Is(err, capture.ErrConflict) {
		t.Fatal("revoke-all at a stale revision", err)
	}
	if r, err := service.RevokePolicySharing(ctx, as(creator.Subject, []string{"maintainers"}), third, 2, "revoke-third"); err != nil || r.Revoked != 1 {
		t.Fatal("revoke-all after stop", r, err)
	}
	if !shares()["capture:"+c8.CaptureID].Revoked || shares()["capture:"+c5.CaptureID].Revoked {
		t.Fatal("revoke-all after stop did not revoke exactly C's share")
	}
	// A's pending capture is never shared after revoke-all, and A claims no
	// further slot.
	f3 := prepare(t, s, c3, false)
	publish(f3)
	if _, exists := shares()["capture:"+c3.CaptureID]; exists {
		t.Fatal("a revoked acceptance's pending capture was shared")
	}
	var revokedAt *time.Time
	if err := admin.QueryRow(ctx, "SELECT sharing_revoked_at FROM policy_acceptance WHERE id=$1", first).Scan(&revokedAt); err != nil || revokedAt == nil {
		t.Fatal("acceptance sharing not marked revoked", err)
	}
	for _, statement := range []string{
		"UPDATE policy_acceptance SET shares_spent=0 WHERE id=$1",
		"UPDATE policy_acceptance SET sharing_revoked_at=NULL,sharing_revoke_key=NULL WHERE id=$1",
		"UPDATE evidence_share SET policy_acceptance_id=NULL WHERE policy_acceptance_id=$1",
	} {
		if _, err := admin.Exec(ctx, statement, first); err == nil {
			t.Fatal("policy sharing state is mutable", statement)
		}
	}
	if _, err := admin.Exec(ctx, "UPDATE policy_acceptance SET sharing_stopped_at=NULL,sharing_stop_key=NULL WHERE id=$1", third); err == nil {
		t.Fatal("a stop is reversible")
	}
	if n := spent(first); n != 3 {
		t.Fatal("counter changed", n)
	}
}
