package integration

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
)

// The real C-07 producer remains mandatory; this wrapper only injects bounded
// response loss and a synchronized pre-SQL pause for the negative regressions.
type querySQLBacking struct {
	current   postgres.ContextQueryBackingGuard
	beforeSQL func(context.Context) error
	after     error
}

func (f *querySQLBacking) WithCurrentQueryBacking(ctx context.Context, p value.ContextQueryPlan, a value.ContextProjectionAuthority, fn func(context.Context) error) error {
	if err := f.current.WithCurrentQueryBacking(ctx, p, a, func(bound context.Context) error {
		if f.beforeSQL != nil {
			if err := f.beforeSQL(bound); err != nil {
				return err
			}
		}
		return fn(bound)
	}); err != nil {
		return err
	}
	return f.after
}

// Worker ownership and joined closure are explicitly synthetic SQL inputs.
type querySQLWorker struct{ worker value.ContextQueryWorker }

func (f *querySQLWorker) WithCurrentProjectionWorker(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, w value.ContextQueryWorker, a value.ContextProjectionAuthority, fn func(context.Context) error) error {
	if w != f.worker || !w.Matches(q) || !r.Valid(time.Now()) || !q.Current(a, time.Now()) {
		return value.ErrUnavailable
	}
	return fn(ctx)
}

type querySQLClosed struct{ batch value.ContextReadBatch }

func (f querySQLClosed) WithProjectionClosed(ctx context.Context, b value.ContextReadBatch, fn func(context.Context) error) error {
	if !f.batch.Equal(b) {
		return value.ErrUnavailable
	}
	return fn(ctx)
}

type querySQLIdentity struct{ identity.Identity }

func (f querySQLIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx.Err() != nil || !f.Identity.Valid(time.Now()) {
		return identity.Identity{}, identity.ErrUnavailable
	}
	return f.Identity, nil
}

// Real PostgreSQL and encrypted, positively closed S3 invocation audit against
// the actual published/verified synthetic context. Current C-03 permissions,
// retained origins, processing and transaction guards are real adapters. Human
// identity, resource qualification and C-14 ownership are explicit fixtures.
func qualifyContextQueries(t *testing.T, f *queryLedgerFixture) {
	ctx, admin, poolFor, store, keys := f.base.ctx, f.base.admin, f.base.fixturePool, f.base.store, f.base.keys
	t.Helper()
	t.Run("context-query-ledger-current-audit-bounds-and-uncertainty", func(t *testing.T) {
		s, published := f.scenario, f.published
		rootID := f.base.input.PermissionRootID
		runtime := poolFor("context_query_runtime", "synthetic-context-query")
		defer runtime.Close()
		keySlots := poolFor("context_query_key_fixture", "synthetic-context-query-key")
		defer keySlots.Close()
		catalogPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
		defer catalogPool.Close()
		journalPool := poolFor("operation_audit_runtime", "synthetic-operation-journal")
		defer journalPool.Close()
		ackPool := poolFor("operation_audit_ack_runtime", "synthetic-operation-ack")
		defer ackPool.Close()
		requireSQLCode := func(err error, code, action string) {
			t.Helper()
			var failure *pgconn.PgError
			if !errors.As(err, &failure) || failure.Code != code {
				t.Fatalf("%s: expected PostgreSQL %s, got %v", action, code, err)
			}
		}
		for _, statement := range []string{
			"UPDATE context_query_backing SET suspended=false", "UPDATE context_query_allocation SET query_limit=query_limit+1",
			"UPDATE context_query SET deadline=deadline+interval '1 second'", "UPDATE context_query_key_binding SET used_roles=0",
			"UPDATE fleet_trust SET recovery_blocked=false", "UPDATE operation_audit SET intent_receipt='{}'::jsonb",
			"INSERT INTO context_query_worker SELECT * FROM context_query_worker LIMIT 0",
			"SELECT context_query_complete_object('{\"a\":1}'::jsonb,ARRAY['a'])",
			"SELECT context_query_outcome_closed('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','{}'::jsonb,'00000000-0000-4000-8000-000000000003')",
		} {
			_, e := runtime.Exec(ctx, statement)
			requireSQLCode(e, "42501", statement)
		}
		raw := func(v any) []byte {
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		e := published.Expectation
		path := f.currentProfile().Path
		principal := s.a.Plan.Input.Executor
		backing := &querySQLBacking{current: f.current}
		worker := &querySQLWorker{}
		ledger, err := postgres.NewContextQueries(ctx, runtime, rootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}, backing, worker)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := postgres.NewContextPublications(ctx, catalogPool, rootID)
		if err != nil {
			t.Fatal(err)
		}
		processing, err := postgres.NewProcessingReads(ctx, catalogPool, rootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		environment := authapp.CurrentProjectionEnvironment{RootID: rootID, InstallationID: f.base.input.InstallationID, Policies: f.current, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}
		authorityGate := authapp.ContextProjectionAuthority{RootID: rootID, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: environment, Now: time.Now}
		scope := value.ContextProjectionScope{RootID: rootID, CaseID: e.CaseID, CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), SourceProjectionDigest: value.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: value.ContextDisplayVersion, Selection: value.LineSelection{LineStart: 1, MaxLines: 14}, Principal: principal}
		authority := func(principal identity.Principal) value.ContextProjectionAuthority {
			t.Helper()
			f.refresh(t)
			n := time.Now().UTC().Truncate(time.Microsecond)
			who := s.a.Eligibility.VerifiedIdentity
			who.Principal = principal
			who.Scopes = []string{"evidence:read"}
			who.VerifiedAt, who.ValidUntil = n, n.Add(5*time.Second)
			selected := scope
			selected.Principal = principal
			a, err := authorityGate.CheckProjectionCurrent(ctx, querySQLIdentity{who}, selected)
			if err != nil {
				t.Fatal("current approved-only query authority", err)
			}
			return a
		}
		plan, err := f.current.ContextQueryPlan(ctx, authority(principal))
		if err != nil {
			t.Fatal("actual accepted query plan", err)
		}
		policy := f.audit.Normal.Policy
		journal, err := postgres.NewHealthyOperationJournal(ctx, journalPool, policy, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := postgres.NewOperationAcknowledgements(ctx, ackPool, plan.RootID, "normal", s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		completions, err := postgres.NewOperationLifecycles(ctx, journalPool, plan.RootID, "normal", s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		objects, err := objectstore.NewClosedOperationAuditObjects(store, policy.StoreID, keys, keys)
		if err != nil {
			t.Fatal(err)
		}
		auditor, err := auditapp.NewHealthyOperationAuditor(policy, journal, ack, &objectstore.OperationAuditObjects{Store: store, Seal: keys, Open: keys}, objects, completions, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		invocation := func(tool string, p identity.Principal, acknowledge bool) (value.ContextQueryRequest, audit.OperationIntent) {
			t.Helper()
			f.refresh(t)
			n := time.Now().UTC().Truncate(time.Microsecond)
			in := audit.OperationIntent{ID: custodyID(), RootID: plan.RootID, TraceID: custodyID(), Name: tool, InputFormat: "context-query-input/v1", MACVersion: "query-fixture-v1", AccountVersion: f.base.input.AccountVersion, Actor: p, PrincipalDigest: artifact.Digest{41}, InputDigest: artifact.Digest{42}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Duration(f.audit.Normal.RetainedSeconds) * time.Second)}
			if acknowledge {
				if err := auditor.Begin(ctx, in); err != nil {
					t.Fatal("healthy query intent", err)
				}
			}
			return value.ContextQueryRequest{Call: value.ContextQueryCall{ID: in.ID, RootID: in.RootID, Tool: in.Name, InputFormat: in.InputFormat, MACVersion: in.MACVersion, InputDigest: in.InputDigest, PrincipalDigest: in.PrincipalDigest, Principal: p, StartedAt: in.CreatedAt, Until: in.RequestUntil, WriteUntil: in.WriteUntil}, OwnerID: custodyID(), HubProcessEpoch: custodyID()}, in
		}
		makeQuery := func(r value.ContextQueryRequest, a value.ContextProjectionAuthority) value.ContextQuery {
			t.Helper()
			p, err := f.current.ContextQueryPlan(ctx, a)
			if err != nil {
				t.Fatal("fresh actual query plan", err)
			}
			// Match the real C-18 clock: deliberately supply nonzero nanoseconds.
			originalNow := time.Now().UTC().Truncate(time.Microsecond).Add(789 * time.Nanosecond)
			q, err := value.NewContextQuery(custodyID(), r.Call.ID, custodyID(), a, p, originalNow)
			if err != nil {
				t.Fatal(err)
			}
			return q
		}
		charged := func(want int64) {
			t.Helper()
			var root, allocation, principal, queries int64
			if err := admin.QueryRow(ctx, "SELECT b.allocated,a.allocated,p.allocated,(SELECT count(*) FROM context_query WHERE root_id=b.root_id) FROM context_query_backing b JOIN context_query_allocation a ON a.root_id=b.root_id JOIN context_query_principal p ON p.root_id=b.root_id WHERE b.root_id=$1", plan.RootID).Scan(&root, &allocation, &principal, &queries); err != nil || root != want || allocation != want || principal != want || queries != want {
				t.Fatal("query commitments mismatch", root, allocation, principal, queries, err)
			}
		}
		// A receipt-free invocation cannot reserve even though source/identity are current.
		unaudited, _ := invocation("get_file_excerpt", plan.Principal, false)
		a := authority(plan.Principal)
		unpaid := makeQuery(unaudited, a)
		if _, err = ledger.AdmitQuery(ctx, unpaid, unaudited, a); err == nil {
			t.Fatal("unaudited query admitted")
		}
		request, intent := invocation("get_file_excerpt", plan.Principal, true)
		a = authority(plan.Principal)
		query := makeQuery(request, a)
		t.Logf("original_evidence_seconds=%.0f original_query_remaining_ms=%d", e.Registration.ExpiresAt.Sub(e.Registration.AnchorAt).Seconds(), time.Until(query.Deadline).Milliseconds())
		accepted, err := ledger.AdmitQuery(ctx, query, request, a)
		if err != nil || !accepted.Fresh {
			t.Fatal("first query", err)
		}
		replay, err := ledger.AdmitQuery(ctx, query, request, a)
		if err != nil || replay.Fresh || !replay.Query.Equal(query) {
			t.Fatal("query replay renewed or dispatched", err)
		}
		charged(1)
		swapped := query
		swapped.Scope.CaseID = custodyID()
		if _, err = ledger.AdmitQuery(ctx, swapped, request, a); err == nil {
			t.Fatal("case swap accepted")
		}
		otherClient := plan.Principal
		otherClient.ClientID = "fixture-other-client"
		if _, err = ledger.LookupQuery(ctx, otherClient, query.ID); err == nil {
			t.Fatal("query handle crossed client")
		}
		worker.worker = value.ContextQueryWorker{QueryID: query.ID, WorkerID: query.WorkerID, PeerID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), Certificate: artifact.Digest{51}, Configuration: path.WorkerConfiguration}
		if _, err = admin.Exec(ctx, "INSERT INTO context_query_worker(query_id,worker_id,binding,proof) VALUES($1,$2,$3,$4)", query.ID, query.WorkerID, raw(worker.worker), raw(map[string]string{"Purpose": value.ContextProjectionPurpose, "Qualification": "synthetic C14 SQL fixture only"})); err != nil {
			t.Fatal(err)
		}
		a = authority(plan.Principal)
		admitted, err := ledger.BeginReadBatch(ctx, query, request, worker.worker, custodyID(), a)
		if err != nil || !admitted.Fresh {
			t.Fatal("batch admission", err)
		}
		batch := admitted.Batch
		var wg sync.WaitGroup
		var mu sync.Mutex
		fresh := 0
		failures := []error{}
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				start, e := ledger.ClaimReadBatch(ctx, batch, a)
				mu.Lock()
				defer mu.Unlock()
				if e != nil {
					failures = append(failures, e)
				} else if start.Fresh {
					fresh++
				}
			}()
		}
		wg.Wait()
		if fresh != 1 || len(failures) > 0 {
			t.Fatal("one-use read start", fresh, failures)
		}
		if _, err = ledger.BeginReadBatch(ctx, query, request, worker.worker, custodyID(), a); err == nil {
			t.Fatal("second batch overlapped active read")
		}
		// Independent narrowly credentialed SQL role can irreversibly spend only
		// three prepaid slots; this is not native key-service qualification.
		if _, err = admin.Exec(ctx, "INSERT INTO context_query_key_binding(batch_id,query_id,binding) VALUES($1,$2,$3)", batch.ID, query.ID, raw(map[string]string{"Purpose": value.ContextProjectionPurpose, "BatchID": batch.ID})); err != nil {
			t.Fatal(err)
		}
		for _, bits := range []int{1, 3, 7} {
			if _, err = keySlots.Exec(ctx, "UPDATE context_query_key_binding SET used_roles=$2 WHERE batch_id=$1", batch.ID, bits); err != nil {
				t.Fatal("key role spend", err)
			}
		}
		for _, bits := range []int{0, 3, 7} {
			_, err = keySlots.Exec(ctx, "UPDATE context_query_key_binding SET used_roles=$2 WHERE batch_id=$1", batch.ID, bits)
			requireSQLCode(err, "23514", "key role reset/reuse")
		}
		// Observe the actual original SQL lease ending, then try with a NEW
		// authorized invocation. Expiry must not turn unknown closure into reuse.
		leaseWait, stopWait := context.WithDeadline(ctx, batch.Until.Add(2*time.Second))
		for {
			var expired bool
			if err = admin.QueryRow(leaseWait, "SELECT clock_timestamp()>$1::timestamptz", batch.Until).Scan(&expired); err != nil {
				stopWait()
				t.Fatal(err)
			}
			if expired {
				break
			}
			select {
			case <-leaseWait.Done():
				stopWait()
				t.Fatal(leaseWait.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		stopWait()
		blockedPoll, _ := invocation("get_query_result", plan.Principal, true)
		a = authority(plan.Principal)
		if err = ledger.AdmitQueryPoll(ctx, query, blockedPoll, a); err != nil {
			t.Fatal(err)
		}
		if _, err = ledger.BeginReadBatch(ctx, query, blockedPoll, worker.worker, custodyID(), a); err == nil {
			t.Fatal("expired lease fabricated private closure")
		}
		charged(1)
		_, err = runtime.Exec(ctx, "UPDATE context_query_batch SET closed=true WHERE id=$1", batch.ID)
		requireSQLCode(err, "23514", "batch close before acknowledged outcome")
		if err = ledger.CompleteReadBatch(ctx, batch, querySQLClosed{batch}); err == nil {
			t.Fatal("closed before acknowledged outcome")
		}
		out := audit.OperationOutcome{Intent: intent, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{61}, OutputBytes: 12, MetadataUntil: intent.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if err = auditor.Finish(ctx, out); err != nil {
			t.Fatal(err)
		}
		if err = ledger.CompleteReadBatch(ctx, batch, querySQLClosed{batch}); err != nil {
			t.Fatal("positive fixture closure", err)
		}
		poll, _ := invocation("get_query_result", plan.Principal, true)
		a = authority(plan.Principal)
		if err = ledger.AdmitQueryPoll(ctx, query, poll, a); err != nil {
			t.Fatal(err)
		}
		second, err := ledger.BeginReadBatch(ctx, query, poll, worker.worker, custodyID(), a)
		if err != nil || !second.Fresh || second.Batch.Generation != 2 {
			t.Fatal("second paid batch", err)
		}
		if _, err = ledger.ClaimReadBatch(ctx, second.Batch, a); err != nil {
			t.Fatal(err)
		}
		// No closure is supplied for the second private operation. Lease expiry,
		// requests and all reads leave its active generation and every charge intact.
		var active string
		var generation int16
		if err = admin.QueryRow(ctx, "SELECT active_batch::text,generation FROM context_query WHERE id=$1", query.ID).Scan(&active, &generation); err != nil || active != second.Batch.ID || generation != 2 {
			t.Fatal("uncertain read lost active slot", err)
		}
		if err = ledger.CompleteReadBatch(ctx, second.Batch, nil); err == nil {
			t.Fatal("missing closure released generation")
		}
		charged(1)
		// Synchronize on a real SQL lock, then invalidate the accepted backing.
		// The earlier independent guard return cannot authorize the later row.
		blockedRequest, _ := invocation("get_file_excerpt", plan.Principal, true)
		blockedAuthority := authority(plan.Principal)
		blockedQuery := makeQuery(blockedRequest, blockedAuthority)
		ready, proceed := make(chan struct{}), make(chan struct{})
		backing.beforeSQL = func(bound context.Context) error {
			close(ready)
			select {
			case <-proceed:
				return nil
			case <-bound.Done():
				return bound.Err()
			}
		}
		result := make(chan error, 1)
		go func() { _, e := ledger.AdmitQuery(ctx, blockedQuery, blockedRequest, blockedAuthority); result <- e }()
		select {
		case <-ready:
		case e := <-result:
			t.Fatal("guard did not reach SQL boundary", e)
		case <-time.After(2 * time.Second):
			t.Fatal("guard boundary not observed")
		}
		blocker, err := admin.Begin(ctx)
		if err != nil {
			close(proceed)
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err = blocker.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", plan.RootID); err != nil {
			close(proceed)
			t.Fatal(err)
		}
		close(proceed)
		observed, stopObserved := context.WithTimeout(ctx, 2*time.Second)
		for {
			var waiting bool
			if err = admin.QueryRow(observed, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='context_query_runtime' AND wait_event_type='Lock')").Scan(&waiting); err != nil {
				stopObserved()
				t.Fatal(err)
			}
			if waiting {
				break
			}
			select {
			case e := <-result:
				stopObserved()
				t.Fatal("admission did not wait for exact SQL lock", e)
			case <-observed.Done():
				stopObserved()
				t.Fatal(observed.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		stopObserved()
		if _, err = admin.Exec(ctx, "UPDATE context_query_backing SET suspended=true WHERE root_id=$1", plan.RootID); err != nil {
			t.Fatal(err)
		}
		if err = blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err = <-result:
			if err == nil {
				t.Fatal("post-lock changed backing authorized query")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked query did not join original deadline")
		}
		backing.beforeSQL = nil
		// Restore only through a fresh independently guarded producer observation.
		f.refresh(t)
		charged(1)
		// A lost guard/commit response returns no Fresh result, while private lookup
		// observes the original committed query and all aggregate accounts stay paid.
		request2, _ := invocation("get_file_excerpt", otherClient, true)
		a2 := authority(otherClient)
		query2 := makeQuery(request2, a2)
		backing.after = errors.New("synthetic postcommit guard loss")
		lost, err := ledger.AdmitQuery(ctx, query2, request2, a2)
		backing.after = nil
		if err == nil || lost.Fresh {
			t.Fatal("postcommit loss returned dispatch authority")
		}
		stored, err := ledger.LookupQuery(ctx, otherClient, query2.ID)
		if err != nil || !stored.Equal(query2) {
			t.Fatal("unknown commit changed original query", err)
		}
		charged(2)
		request3, _ := invocation("get_file_excerpt", plan.Principal, true)
		a3 := authority(plan.Principal)
		query3 := makeQuery(request3, a3)
		if _, err = ledger.AdmitQuery(ctx, query3, request3, a3); err == nil {
			t.Fatal("aggregate root/workload/principal quota refilled")
		}
		charged(2)
		// Two polls were already admitted. The remaining original allowance
		// permits exactly two, regardless of active generation or new IDs.
		for i := 0; i < 3; i++ {
			poll, _ := invocation("get_query_result", plan.Principal, true)
			a := authority(plan.Principal)
			err := ledger.AdmitQueryPoll(ctx, query, poll, a)
			if (i < 2 && err != nil) || (i == 2 && err == nil) {
				t.Fatalf("finite paid poll allowance %d: %v (original query remaining %s, original evidence remaining %s)", i, err, time.Until(query.Deadline), time.Until(e.Registration.ExpiresAt))
			}
		}
		for _, statement := range []string{"UPDATE context_query SET generation=0 WHERE id=$1", "UPDATE context_query SET active_batch=NULL WHERE id=$1", "UPDATE context_query SET deadline=deadline+interval '1 second' WHERE id=$1", "DELETE FROM context_query WHERE id=$1"} {
			_, err = admin.Exec(ctx, statement, query.ID)
			requireSQLCode(err, "23514", statement)
		}
		t.Logf("verified real SQL/S3 query accounting and healthy invocation lineage; C07 acceptance and C03 environment are actual; resource report/native guards and C14 ownership remain synthetic; original query=%s, uncertain generation=%d, charged queries=2", query.ID, generation)
	})
}
