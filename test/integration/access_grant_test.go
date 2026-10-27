package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyAccessGrants (ADR-249) runs the AccessGrant ledger through the
// compiled hub-runtime grants on real PostgreSQL, the actual accepted
// permission projection (with an added action-approver binding) and an
// actually published artifact: atomic approval with self-approval refused by
// the service and by SQL, exact children after verified commit, one finite
// pool under concurrent use, concurrent use against revocation, spend that
// survives a restart, expiry and the audit-lane registration.
func qualifyAccessGrants(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, publishAuthority func() error, releasePermissionBurst func()) {
	t.Helper()
	// The concurrent phases grow the shared permission reader's pool; release
	// its idle connections so later suites keep their connection budget.
	t.Cleanup(releasePermissionBurst)
	// An action-approver group joins the accepted projection.
	approver := s.batch.Bases[0]
	approver.Resource.UID = custodyID()
	approver.Subjects = []cfg.Subject{{Kind: "Group", Issuer: approver.Subjects[0].Issuer, ID: "approvers"}}
	approver.Roles = []string{"action-approver"}
	approver.ScopeDigest = configapp.PermissionScopeDigest(approver)
	batch := s.batch
	batch.Bases = append(slices.Clone(s.batch.Bases), approver)
	batch.RequestID, batch.InputDigest, batch.Initial = custodyID(), artifact.Digest{byte(len(batch.Bases)), 9}, nil
	batch.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	batch.FreshUntil = batch.ObservedAt.Add(5 * time.Second)
	accepted, err := s.p.AcceptPermissions(ctx, batch)
	if err != nil {
		t.Fatal("approver binding", err)
	}
	batch.ExpectedSequence = accepted.Sequence
	for i := 0; i < 2; i++ {
		if err := publishAuthority(); err != nil {
			t.Fatal(err)
		}
	}
	refresh := func() {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		b := batch
		b.ObservedAt, b.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	role := narrowRole(t, ctx, admin, "grant_hub_", "synthetic-grant-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing compiled hub grants")
		}
		return grants
	})
	pool := poolFor(role, "synthetic-grant-hub")
	t.Cleanup(pool.Close)
	store, err := postgres.NewAccessGrants(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64
	svc := func(store authapp.GrantStore) authapp.GrantService {
		return authapp.GrantService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Permissions: s.p, Store: store, Recovery: s.recovery.reader, NewID: func() string { ids.Add(1); return custodyID() }, Now: time.Now}
	}
	grants := svc(store)
	as := func(subject, client string, groups []string, stepUp bool, scopes ...string) identities.CurrentIdentity {
		t.Helper()
		refresh()
		now := time.Now().UTC().Truncate(time.Microsecond)
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Principal.ClientID, i.Groups, i.Scopes = subject, client, groups, scopes
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		if stepUp {
			i.Assurance = identity.Assurance{ACR: "gold", AuthenticatedAt: now.Add(-time.Minute), StepUpUntil: now.Add(4 * time.Second)}
		}
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	client := s.a.Eligibility.VerifiedIdentity.Principal.ClientID
	requester := func(c string) identities.CurrentIdentity {
		return as("synthetic-dev", c, []string{"maintainers"}, false, "evidence:read", "evidence:capture", "evidence:download")
	}
	lead := func() identities.CurrentIdentity {
		return as("synthetic-lead", client, []string{"approvers"}, true, "evidence:read")
	}
	target := authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}
	scope := []byte(`{"schemaVersion":"recorder-preview/v1","synthetic":"` + custodyID() + `"}`)
	input := func(capture string, access *authorization.ResultAccess, key string) authapp.GrantRequestInput {
		i := s.a.Eligibility.VerifiedIdentity.Principal
		i.Subject = "synthetic-dev"
		return authapp.GrantRequestInput{PreviewID: custodyID(), CaptureID: capture, Actor: i, Target: target, Scope: scope, ExecutionDigest: sha256.Sum256(scope), DataClass: "extract",
			Reasons: []authorization.SensitiveReason{{ActionID: "a1", Code: "rawBytePredicate"}}, Review: authapp.GrantReview{Namespace: "app", WorkloadKind: "Deployment", WorkloadName: "api", PodName: "api-123", Actions: []authapp.GrantReviewAction{{ActionID: "a1", Kind: "packetCapture"}}, Deadline: time.Now().Add(5 * time.Minute)},
			Lifetime: authorization.GrantDefaultLifetime, ResultAccess: access, IdempotencyKey: key}
	}
	access := &authorization.ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{client, "synthetic-agent"}, MaxArtifacts: 1, MaxBytes: 100, MaxOperations: 1000, NotAfter: time.Now().Add(2 * time.Hour).UTC().Truncate(time.Microsecond)}

	// The published capture's request: pending, then self-approval refused
	// through another client, by service and by SQL.
	first := input(e.CaptureUID, access, "grant-1")
	pending, replay, err := grants.Request(ctx, requester(client), first)
	if err != nil || replay || pending.Phase(time.Now()) != authorization.GrantPending {
		t.Fatal("request", err, replay)
	}
	if again, replay, err := grants.Request(ctx, requester(client), first); err != nil || !replay || again.ID != pending.ID {
		t.Fatal("request replay", err)
	}
	// The same key for another review (another preview) is a conflict.
	if _, _, err := grants.Request(ctx, requester(client), input(e.CaptureUID, access, "grant-1")); !errors.Is(err, authapp.ErrGrantConflict) {
		t.Fatal("changed request under the same key", err)
	}
	if _, _, err := grants.Request(ctx, requester(client), input(e.CaptureUID, access, "grant-other-key")); !errors.Is(err, authapp.ErrGrantConflict) {
		t.Fatal("second request for one capture", err)
	}
	self := as("synthetic-dev", "synthetic-agent", []string{"maintainers", "approvers"}, true, "evidence:read")
	if _, _, err := grants.Decide(ctx, self, pending.ID, true, "self", "self"); !errors.Is(err, authorization.ErrSelfApproval) {
		t.Fatal("self-approval through another client", err)
	}
	_, err = pool.Exec(ctx, "UPDATE access_grant SET decision='approved',approver_issuer=requester_issuer,approver_subject=requester_subject,approver_client='synthetic-agent',decision_reason='x',decision_acr='gold',decision_auth_time=clock_timestamp(),decided_at=clock_timestamp(),decision_key='sql',expires_at=clock_timestamp()+interval '1 hour',revision=2 WHERE id=$1", pending.ID)
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatal("SQL accepted a self-approval", err)
	}
	// No step-up: refused. A non-approver: refused.
	if _, _, err := grants.Decide(ctx, as("synthetic-lead", client, []string{"approvers"}, false, "evidence:read"), pending.ID, true, "x", "x"); !errors.Is(err, authorization.ErrStepUpRequired) {
		t.Fatal("approval without step-up", err)
	}
	if _, _, err := grants.Decide(ctx, as("synthetic-other", client, []string{"maintainers"}, true, "evidence:read"), pending.ID, true, "x", "x2"); !errors.Is(err, authorization.ErrNotApprover) {
		t.Fatal("approval without the approver role", err)
	}
	// Two approvers race: exactly one decision is recorded.
	var decisions sync.WaitGroup
	results := make(chan error, 4)
	leads := []identities.CurrentIdentity{lead(), lead(), lead(), lead()}
	for n := 0; n < 4; n++ {
		decisions.Add(1)
		go func(n int) {
			defer decisions.Done()
			_, _, err := grants.Decide(ctx, leads[n], pending.ID, true, "incident 42", "decide-"+string(rune('a'+n)))
			results <- err
		}(n)
	}
	decisions.Wait()
	close(results)
	won := 0
	for err := range results {
		if err == nil {
			won++
		} else if !errors.Is(err, authorization.ErrGrantNotPending) {
			t.Fatal("concurrent decision", err)
		}
	}
	approved, err := store.Grant(ctx, pending.ID)
	if err != nil || won != 1 || approved.Phase(time.Now()) != authorization.GrantApproved || approved.Revision != 2 || approved.Decision.ACR != "gold" {
		t.Fatal("atomic approval", won, err)
	}
	// Immutable apart from the decision, revocation and monotonic spend.
	for _, sql := range []string{"UPDATE access_grant SET data_class='raw' WHERE id=$1", "UPDATE access_grant SET bytes_spent=0 WHERE id=$1", "UPDATE access_grant SET expires_at=expires_at+interval '1 hour' WHERE id=$1"} {
		if _, err := admin.Exec(ctx, sql, pending.ID); err == nil {
			t.Fatalf("grant changed in place: %s", sql)
		}
	}
	if _, err := pool.Exec(ctx, "DELETE FROM access_grant WHERE id=$1", pending.ID); !errors.As(err, &pgerr) || pgerr.Code != "42501" {
		t.Fatal("runtime role deleted a grant", err)
	}
	if _, _, err := grants.Covering(ctx, requester(client), e.CaptureUID, pending.ExecutionDigest, target); err != nil {
		t.Fatal("approved grant does not cover its plan", err)
	}

	// Exact children after verified commit: only the published artifact of
	// this capture; repeated delivery and a second client add no artifact.
	output := authorization.VerifiedOutput{CaptureID: e.CaptureUID, ActionID: "a1", ArtifactID: e.Registration.Location.ArtifactID, ExecutionDigest: pending.ExecutionDigest, ArtifactDigest: artifact.Digest{7}, Target: target}
	unknown := output
	unknown.ArtifactID = custodyID()
	if _, _, err := grants.Materialize(ctx, pending.ID, client, unknown); !errors.Is(err, authorization.ErrGrantScope) {
		t.Fatal("unpublished artifact became a child", err)
	}
	child, replay, err := grants.Materialize(ctx, pending.ID, client, output)
	if err != nil || replay {
		t.Fatal("materialize", err)
	}
	if again, replay, err := grants.Materialize(ctx, pending.ID, client, output); err != nil || !replay || again.ID != child.ID {
		t.Fatal("duplicate commit delivery", err)
	}
	agentChild, _, err := grants.Materialize(ctx, pending.ID, "synthetic-agent", output)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := store.Grant(ctx, pending.ID); g.Spent.Artifacts != 1 {
		t.Fatal("a second client charged another artifact", g.Spent)
	}
	if _, _, err := grants.Materialize(ctx, pending.ID, "synthetic-cli", output); !errors.Is(err, authorization.ErrGrantScope) {
		t.Fatal("unlisted client", err)
	}

	// One finite pool under concurrency: 8 uses of 10 bytes, then 6 more
	// against the remaining 20 bytes, across both clients; exactly ten succeed
	// in total and nothing refills.
	var spent atomic.Int64
	var wg sync.WaitGroup
	devConsole, devAgent := requester(client), requester("synthetic-agent")
	for n := 0; n < 14; n++ {
		if n == 8 {
			wg.Wait()
			releasePermissionBurst()
		}
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			who, c := devConsole, child
			if n%2 == 1 {
				who, c = devAgent, agentChild
			}
			// A reservation that waited past the one-second lock timeout is
			// unavailable and charged nothing; the client retries it with the
			// same use ID, which can never charge twice.
			use := custodyID()
			for attempt := 0; ; attempt++ {
				_, _, err := grants.Use(ctx, who, c.ID, use, authorization.GrantUse{Operation: authorization.GrantDownloadOperation, Bytes: 10, Operations: 1})
				switch {
				case err == nil:
					spent.Add(10)
				case errors.Is(err, authapp.ErrGrantUnavailable) && attempt < 20:
					time.Sleep(time.Duration(10+attempt*10) * time.Millisecond)
					continue
				case !errors.Is(err, authorization.ErrGrantPoolExhausted):
					t.Error("concurrent use", err)
				}
				return
			}
		}(n)
	}
	wg.Wait()
	releasePermissionBurst()
	g, err := store.Grant(ctx, pending.ID)
	if err != nil || spent.Load() != 100 || g.Spent.Bytes != 100 || g.Spent.Operations != 10 {
		t.Fatal("pool accounting", spent.Load(), g.Spent, err)
	}
	// Spend survives a restart: a new store instance sees it, and the retry
	// of a recorded use is a replay without another charge.
	restarted, err := postgres.NewAccessGrants(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	if g, err := restarted.Grant(ctx, pending.ID); err != nil || g.Spent.Bytes != 100 {
		t.Fatal("spend lost on restart", err)
	}

	// Concurrent use against revocation on a fresh grant: after the
	// revocation commits no use succeeds and the pool is never exceeded.
	second, _, err := grants.Request(ctx, requester(client), input(custodyID(), &authorization.ResultAccess{ActionIDs: []string{"a1"}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{client}, MaxArtifacts: 1, MaxBytes: 1 << 20, MaxOperations: 10000, NotAfter: access.NotAfter}, "grant-2"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := grants.Decide(ctx, lead(), second.ID, true, "incident 43", "decide-2"); err != nil {
		t.Fatal(err)
	}
	// Its child is registered directly (its synthetic capture has no published
	// artifact); the service already proved the published-locator rule above.
	childID := custodyID()
	digest := sha256.Sum256([]byte("synthetic artifact"))
	if _, err := admin.Exec(ctx, "INSERT INTO access_grant_child(id,root_id,parent_id,capture_id,action_id,artifact_id,artifact_digest,client_id) VALUES($1,$2,$3,$4,'a1',$5,$6,$7)", childID, s.a.RootID, second.ID, second.CaptureID, custodyID(), digest[:], client); err != nil {
		t.Fatal(err)
	}
	var after atomic.Int64
	var revokedAt atomic.Value
	dev, revoker := requester(client), lead()
	stop := make(chan struct{})
	var users sync.WaitGroup
	for n := 0; n < 3; n++ {
		users.Add(1)
		go func() {
			defer users.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				started := time.Now()
				_, _, err := grants.Use(ctx, dev, childID, custodyID(), authorization.GrantUse{Operation: authorization.GrantDownloadOperation, Bytes: 1, Operations: 1})
				if r, ok := revokedAt.Load().(time.Time); ok && err == nil && started.After(r) {
					after.Add(1)
				}
				if err != nil && !errors.Is(err, authorization.ErrGrantRevoked) && !errors.Is(err, authapp.ErrGrantUnavailable) {
					t.Error("use during revocation", err)
					return
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	if _, _, err := grants.Revoke(ctx, revoker, second.ID, 2, "stop"); err != nil {
		t.Fatal(err)
	}
	revokedAt.Store(time.Now())
	time.Sleep(200 * time.Millisecond)
	close(stop)
	users.Wait()
	releasePermissionBurst()
	final, err := store.Grant(ctx, second.ID)
	if err != nil || after.Load() != 0 || final.Phase(time.Now()) != authorization.GrantRevoked || final.Spent.Bytes > final.ResultAccess.MaxBytes {
		t.Fatal("use after revocation", after.Load(), err)
	}
	if _, _, err := grants.Covering(ctx, requester(client), second.CaptureID, second.ExecutionDigest, target); !errors.Is(err, authorization.ErrGrantRevoked) {
		t.Fatal("revoked grant covers", err)
	}

	// Expiry: a result-access end two seconds away caps the grant.
	short := *access
	short.NotAfter = time.Now().Add(2 * time.Second).UTC().Truncate(time.Microsecond)
	third, _, err := grants.Request(ctx, requester(client), input(custodyID(), &short, "grant-3"))
	if err != nil {
		t.Fatal(err)
	}
	approvedShort, _, err := grants.Decide(ctx, lead(), third.ID, true, "short", "decide-3")
	if err != nil || !approvedShort.ExpiresAt.Equal(short.NotAfter) {
		t.Fatal("not_after cap", err)
	}
	time.Sleep(time.Until(short.NotAfter) + 50*time.Millisecond)
	if _, _, err := grants.Covering(ctx, requester(client), third.CaptureID, third.ExecutionDigest, target); !errors.Is(err, authorization.ErrGrantExpired) {
		t.Fatal("expired grant covers", err)
	}

	// The four operations are registered on the normal audit lane.
	for _, name := range []string{"get_grant", "list_reviews", "decide_review", "revoke_grant"} {
		var lane string
		var valid bool
		if err := admin.QueryRow(ctx, "SELECT operation_audit_lane($1), operation_audit_human_input_valid($1,'context-input/v1')", name).Scan(&lane, &valid); err != nil || lane != "normal" || !valid {
			t.Fatal("audit lane", name, lane, valid, err)
		}
	}
}
