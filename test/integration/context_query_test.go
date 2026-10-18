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
	"github.com/jackc/pgx/v5/pgxpool"
)

// These explicit synthetic guards qualify SQL accounting/lineage only. They
// are not a protected C-07 producer, enrolled C-14 worker or native key reader.
type querySQLBacking struct {
	admin *pgxpool.Pool
	plan  value.ContextQueryPlan
	after error
}

func (f *querySQLBacking) WithCurrentQueryBacking(ctx context.Context, p value.ContextQueryPlan, a value.ContextProjectionAuthority, fn func(context.Context) error) error {
	if p.AcceptanceID != f.plan.AcceptanceID || p.RootID != f.plan.RootID || p.InstallationID != f.plan.InstallationID || p.AllocationID != f.plan.AllocationID || p.Profile != f.plan.Profile || p.PoolSource != f.plan.PoolSource || p.PolicySource != f.plan.PolicySource || !p.HardUntil.Equal(f.plan.HardUntil) || !p.EffectsUntil.Equal(f.plan.EffectsUntil) || !p.CleanupUntil.Equal(f.plan.CleanupUntil) || !p.RetireBy.Equal(f.plan.RetireBy) || a.Environment.Path != f.plan.Profile.Path {
		return value.ErrUnavailable
	}
	// Fixture-only current accepted source observation; done before SQL locks.
	n := time.Now().UTC().Truncate(time.Microsecond)
	if _, e := f.admin.Exec(ctx, "UPDATE context_query_backing SET observed_at=$2,fresh_until=$3 WHERE root_id=$1", p.RootID, n, n.Add(5*time.Second)); e != nil {
		return e
	}
	if e := fn(ctx); e != nil {
		return e
	}
	return f.after
}

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

type querySQLEnvironment struct {
	root, installation string
	path               value.ContextProjectionPath
	policy             identity.Revision
	recovery           *postgres.RecoveryReader
	processing         *postgres.ProcessingReads
}

func (f querySQLEnvironment) ProjectionEnvironment(ctx context.Context, r authapp.ContextProjectionEvidence, p identity.Principal) (value.ContextProjectionEnvironment, error) {
	recovery, e := f.recovery.RecoveryState(ctx)
	if e != nil {
		return value.ContextProjectionEnvironment{}, e
	}
	processing, e := f.processing.ContextProjectionProcessing(ctx, r, recovery)
	if e != nil {
		return value.ContextProjectionEnvironment{}, e
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	return value.ContextProjectionEnvironment{RootID: f.root, InstallationID: f.installation, Region: f.path.AcquisitionRegion, StoreID: r.Retained.Registration.StoreID, Location: r.Retained.Registration.Location, Principal: p, PolicyRevision: f.policy, Recovery: recovery, Processing: processing, Path: f.path, ObservedAt: n, ValidUntil: minPublicationTime(r.ValidUntil, minPublicationTime(recovery.FreshUntil, processing.ValidUntil))}, nil
}

// Real PostgreSQL and encrypted, positively closed S3 invocation audit against
// the actual published/verified synthetic context. Current C-03 permissions,
// retained origins, processing and transaction guards are real adapters. Human
// identity, resource qualification and C-14 ownership are explicit fixtures.
func qualifyContextQueries(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, create func(*testing.T) (captureAdmissionScenario, artifact.PublishedContext)) {
	t.Helper()
	t.Run("context-query-ledger-current-audit-bounds-and-uncertainty", func(t *testing.T) {
		s, published := create(t)
		sources := startNativeScenarioSources(t, ctx, admin, s)
		defer sources.Close()
		s.nativeSources = sources
		ctx = sources.ctx
		runtime := poolFor("context_query_runtime", "synthetic-context-query")
		defer runtime.Close()
		keySlots := poolFor("context_query_key_fixture", "synthetic-context-query-key")
		defer keySlots.Close()
		catalogPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
		defer catalogPool.Close()
		configPool := poolFor("operation_audit_config_runtime", "synthetic-operation-config")
		defer configPool.Close()
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
		rev := func(mark byte) identity.Revision {
			return identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{mark}}
		}
		path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: custodyID(), TargetClusterID: e.Registration.Location.ClusterID, StoreID: e.Registration.StoreID, StorageRegion: "fixture-region", AcquisitionClusterID: e.Registration.Location.ClusterID, AcquisitionRegion: "fixture-region", ConnectorClusterID: e.Registration.Location.ClusterID, ConnectorRegion: "fixture-region", HubClusterID: e.Registration.Location.ClusterID, HubRegion: "fixture-region", WorkerConfiguration: rev(11), HubConfiguration: rev(12)}
		profile := value.ContextQueryResourceProfile{ID: custodyID(), Source: rev(13), Qualification: rev(14), Path: path, Lifetime: 60 * time.Second, PollLimit: 4, ControlTransitionLimit: 32,
			Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
			Cost:   value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * value.ContextBatchReadWork, StructuredBytes: 2 * value.ContextResultBytes, WireBytes: 2 * value.ContextWireBytes, UnwrapAttempts: 6, ProviderRequests: 32, AuthenticationRequests: 32, SigningAttempts: 2, AuditObjects: 32, SQLRows: 32, SQLBytes: 1 << 20, WALBytes: 16 << 20, BackupBytes: 4 << 20}}
		n := time.Now().UTC().Truncate(time.Microsecond)
		plan := value.ContextQueryPlan{AcceptanceID: custodyID(), AccountID: custodyID(), AllocationID: custodyID(), RootID: s.a.RootID, InstallationID: s.recovery.installation, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, AllocationRevision: 1, PoolSource: rev(15), PolicySource: rev(16), Principal: s.a.Plan.Input.Executor, Profile: profile, ObservedAt: n, ValidUntil: n.Add(5 * time.Second), HardUntil: n.Add(2 * time.Minute), EffectsUntil: n.Add(4 * time.Minute), CleanupUntil: n.Add(5 * time.Minute), RetireBy: n.Add(time.Hour)}
		// Two fully reserved query obligations, across all clients. These cost
		// figures are synthetic arithmetic inputs, not measured backend capacity.
		envelope := map[string]int64{}
		costBytes := raw(profile.Cost)
		var cost map[string]int64
		if err := json.Unmarshal(costBytes, &cost); err != nil {
			t.Fatal(err)
		}
		for name, v := range cost {
			envelope[name] = v * 2
		}
		for name, v := range map[string]int64{"CPUMilli": profile.Worker.CPUMilli, "MemoryBytes": profile.Worker.MemoryBytes, "WorkerTransientBytes": profile.Worker.WorkerTransientBytes, "HubTransientBytes": profile.Worker.HubTransientBytes, "ProviderConcurrency": profile.Worker.ProviderConcurrency, "AuthenticationConcurrency": profile.Worker.AuthenticationConcurrency} {
			envelope[name] = v * 2
		}
		if _, err := admin.Exec(ctx, "INSERT INTO context_query_backing(root_id,installation_id,acceptance_id,profile,qualification,envelope,query_limit,principal_query_limit,principal_account_limit,allocation_limit,observed_at,fresh_until,hard_until,effects_until,cleanup_until,retire_by,suspended) VALUES($1,$2,$3,$4,$5,$6,2,2,2,1,$7,$8,$9,$10,$11,$12,false)", plan.RootID, plan.InstallationID, plan.AcceptanceID, raw(profile), raw(profile.Qualification), raw(envelope), n, n.Add(5*time.Second), plan.HardUntil, plan.EffectsUntil, plan.CleanupUntil, plan.RetireBy); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, "INSERT INTO context_query_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,revision,pool_source,policy_source,query_limit) VALUES($1,$2,$3,$4,$5,1,$6,$7,2)", plan.AllocationID, plan.RootID, plan.ClusterID, plan.NamespaceUID, plan.WorkloadUID, raw(plan.PoolSource), raw(plan.PolicySource)); err != nil {
			t.Fatal(err)
		}
		backing := &querySQLBacking{admin: admin, plan: plan}
		worker := &querySQLWorker{}
		ledger, err := postgres.NewContextQueries(ctx, runtime, plan.RootID, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}, backing, worker)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := postgres.NewContextPublications(ctx, catalogPool, plan.RootID)
		if err != nil {
			t.Fatal(err)
		}
		processing, err := postgres.NewProcessingReads(ctx, catalogPool, plan.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		environment := querySQLEnvironment{root: plan.RootID, installation: plan.InstallationID, path: path, policy: plan.PolicySource, recovery: s.recovery.reader, processing: processing}
		authorityGate := authapp.ContextProjectionAuthority{RootID: plan.RootID, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: nativeFixtureRetainedPolicies(s), Now: time.Now}, Environment: environment, Now: time.Now}
		scope := value.ContextProjectionScope{RootID: plan.RootID, CaseID: e.CaseID, CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, ClusterID: plan.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), SourceProjectionDigest: value.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: value.ContextDisplayVersion, Selection: value.LineSelection{LineStart: 1, MaxLines: 14}, Principal: plan.Principal}
		authority := func(principal identity.Principal) value.ContextProjectionAuthority {
			t.Helper()
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
		config, err := postgres.New(ctx, configPool)
		if err != nil {
			t.Fatal(err)
		}
		n = time.Now().UTC().Truncate(time.Microsecond)
		if err = config.ProvisionOperationAuditPool(ctx, auditapp.OperationAuditPool{RootID: plan.RootID, Lane: "normal", AccountVersion: "query-fixture-v1", Accounts: 2, RecordsPerAccount: 32, RetainedSeconds: 3600, ObservedAt: n, FreshUntil: n.Add(5 * time.Second), ValidUntil: n.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		policy := audit.OperationLifecyclePolicy{RootID: plan.RootID, Lane: "normal", InstallationID: plan.InstallationID, StoreID: e.Registration.StoreID, PolicyID: custodyID(), BackupProfileID: custodyID(), PolicyDigest: artifact.Digest{31}, BackupProfileDigest: artifact.Digest{32}, BackingRevision: 1, MetadataSlots: 64, MaxPurgeLeases: 2, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), History: &audit.OperationHistoryQualification{ID: custodyID(), Digest: artifact.Digest{33}, Layout: audit.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}}
		bb, ww := policy.History.SlotBacking(policy.MaxPurgeLeases)
		policy.BackupReservedBytes, policy.WALReservedBytes = bb*policy.MetadataSlots, ww*policy.MetadataSlots
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
			n := time.Now().UTC().Truncate(time.Microsecond)
			in := audit.OperationIntent{ID: custodyID(), RootID: plan.RootID, TraceID: custodyID(), Name: tool, InputFormat: "context-query-input/v1", MACVersion: "query-fixture-v1", AccountVersion: "query-fixture-v1", Actor: p, PrincipalDigest: artifact.Digest{41}, InputDigest: artifact.Digest{42}, CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
			if acknowledge {
				if err := auditor.Begin(ctx, in); err != nil {
					t.Fatal("healthy query intent", err)
				}
			}
			return value.ContextQueryRequest{Call: value.ContextQueryCall{ID: in.ID, RootID: in.RootID, Tool: in.Name, InputFormat: in.InputFormat, MACVersion: in.MACVersion, InputDigest: in.InputDigest, PrincipalDigest: in.PrincipalDigest, Principal: p, StartedAt: in.CreatedAt, Until: in.RequestUntil, WriteUntil: in.WriteUntil}, OwnerID: custodyID(), HubProcessEpoch: custodyID()}, in
		}
		makeQuery := func(r value.ContextQueryRequest, a value.ContextProjectionAuthority) value.ContextQuery {
			t.Helper()
			p := plan
			p.Principal = a.Scope.Principal
			p.ObservedAt, p.ValidUntil = a.CheckedAt, a.ValidUntil
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
		blocker, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		if _, err = blocker.Exec(ctx, "SELECT id FROM permission_stream WHERE id=$1 FOR UPDATE", plan.RootID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, e := ledger.AdmitQuery(ctx, blockedQuery, blockedRequest, blockedAuthority); result <- e }()
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
		if _, err = admin.Exec(ctx, "UPDATE context_query_backing SET suspended=false WHERE root_id=$1", plan.RootID); err != nil {
			t.Fatal(err)
		}
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
				t.Fatal("finite paid poll allowance", i, err)
			}
		}
		for _, statement := range []string{"UPDATE context_query SET generation=0 WHERE id=$1", "UPDATE context_query SET active_batch=NULL WHERE id=$1", "UPDATE context_query SET deadline=deadline+interval '1 second' WHERE id=$1", "DELETE FROM context_query WHERE id=$1"} {
			_, err = admin.Exec(ctx, statement, query.ID)
			requireSQLCode(err, "23514", statement)
		}
		t.Logf("verified real SQL/S3 query accounting and healthy invocation lineage; C07/C14 inputs remain synthetic; original query=%s, uncertain generation=%d, charged queries=2", query.ID, generation)
	})
}
