package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	authorization "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func comparisonLedgerQualification(q *capacityapp.ContextQueryQualification) {
	q.Profile.Worker.MemoryBytes, q.Profile.Worker.WorkerTransientBytes = value.ProfileComparisonWorkerBytes, value.ProfileComparisonWorkerBytes
	q.RootQueries, q.PrincipalQueries, q.WorkloadQueries, q.WorkloadAccounts = 100, 100, 40, 2
	q.History.RowBytes = 128 << 10
	q.Profile.Cost.SQLBytes, q.Profile.Cost.BackupBytes = 8<<20, 16<<20
}

func TestProfileComparisonLedgerOriginalQualification(t *testing.T) {
	qualified, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "fixture-accounts-v1")
	f := &capacitySQLFixture{qualification: qualified, template: source}
	queryLedgerQualification(t, f)
	comparisonLedgerQualification(f.qualification.ContextQuery)
	var err error
	f.qualification.ContextQuery.Envelope, err = f.qualification.ContextQuery.Required()
	if err != nil || !f.qualification.Valid() {
		t.Fatal("combined original comparison SQL fixture qualification", err)
	}
	pool, err := capacityapp.CompileProtectedPoolPlan(source, source.Pools[0].Resource.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = capacityapp.CompileQualifiedRootBacking(f.qualification, pool); err != nil {
		t.Fatal("combined comparison resource reservation", err)
	}
}

// Real133 SQL, protected capacity, published encrypted pprof and C3 authority.
// C14 ownership/worker pins are explicit fixture facts. Direct key-role writes
// below qualify SQL masks only, never mTLS/key-service use or native delivery.
func TestProfileComparisonQueryLedgerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyProfileComparisonQueries, true, true)
	})
}

func qualifyProfileComparisonQueries(t *testing.T, f *queryLedgerFixture) {
	ctx, admin, poolFor := f.base.ctx, f.base.admin, f.base.fixturePool
	root := f.base.input.PermissionRootID
	s := f.scenario
	expected := f.published.Expectation
	raw := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	runtime := poolFor("context_query_runtime", "synthetic-context-query")
	defer runtime.Close()
	slots := poolFor("context_query_key_fixture", "synthetic-context-query-key")
	defer slots.Close()
	catalogPool := poolFor("context_catalog_read_runtime", "synthetic-context-read")
	defer catalogPool.Close()
	journalPool := poolFor("operation_audit_runtime", "synthetic-operation-journal")
	defer journalPool.Close()
	ackPool := poolFor("operation_audit_ack_runtime", "synthetic-operation-ack")
	defer ackPool.Close()
	catalog, e := postgres.NewContextPublications(ctx, catalogPool, root)
	if e != nil {
		t.Fatal(e)
	}
	processing, e := postgres.NewProcessingReads(ctx, catalogPool, root, s.recovery.guard)
	if e != nil {
		t.Fatal(e)
	}
	environment := authapp.CurrentProjectionEnvironment{RootID: root, InstallationID: f.base.input.InstallationID, Policies: f.policies, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}
	gate := authapp.ContextProjectionAuthority{RootID: root, Permissions: s.p, Catalog: catalog, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Environment: environment, Now: time.Now}
	principal := s.a.Plan.Input.Executor
	scope := value.ContextProjectionScope{RootID: root, CaseID: expected.CaseID, CaptureID: expected.CaptureUID, ArtifactID: expected.Registration.Location.ArtifactID, ClusterID: expected.Registration.Location.ClusterID, NamespaceUID: expected.NamespaceUID, WorkloadUID: expected.WorkloadUID, PodUID: expected.PodUID, Version: evidence.ContextCopiesDigest(f.published.Copies), SourceFormat: artifact.PprofFormat, DisplayVersion: value.ProfileComparisonDisplayVersion, NativeType: artifact.PprofArtifact, Profile: value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}, Principal: principal}
	scope.Comparison = value.ProfileComparisonWindow{Normalization: value.ProfileComparisonRaw, Baseline: value.ProfileComparisonBaseline{CaseID: scope.CaseID, ArtifactID: scope.ArtifactID, CaptureID: scope.CaptureID, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID, Version: scope.Version}}
	authority := func() value.ContextProjectionAuthority {
		t.Helper()
		f.refresh(t)
		now := time.Now().UTC().Truncate(time.Microsecond)
		who := s.a.Eligibility.VerifiedIdentity
		who.Scopes = []string{"evidence:read"}
		who.VerifiedAt, who.ValidUntil = now, now.Add(5*time.Second)
		a, err := gate.CheckProjectionCurrent(ctx, querySQLIdentity{who}, scope)
		if err != nil {
			var step interface{ FixedStep() string }
			if errors.As(err, &step) {
				t.Log("pair C3 refusal", step.FixedStep())
			}
			t.Fatal("paired current authority", err)
		}
		return a
	}
	ownership := &querySQLWorker{}
	ledger, e := postgres.NewContextQueries(ctx, runtime, root, postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}, f.current, ownership)
	if e != nil {
		t.Fatal(e)
	}
	policy := f.audit.Normal.Policy
	journal, e := postgres.NewHealthyOperationJournal(ctx, journalPool, policy, s.recovery.guard)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := postgres.NewOperationAcknowledgements(ctx, ackPool, root, "normal", s.recovery.guard)
	if e != nil {
		t.Fatal(e)
	}
	completions, e := postgres.NewOperationLifecycles(ctx, journalPool, root, "normal", s.recovery.guard)
	if e != nil {
		t.Fatal(e)
	}
	objects, e := objectstore.NewClosedOperationAuditObjects(f.base.store, policy.StoreID, f.base.keys, f.base.keys)
	if e != nil {
		t.Fatal(e)
	}
	auditor, e := auditapp.NewHealthyOperationAuditor(policy, journal, ack, &objectstore.OperationAuditObjects{Store: f.base.store, Seal: f.base.keys, Open: f.base.keys}, objects, completions, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	invocation := func(tool string) (value.ContextQueryRequest, audit.OperationIntent) {
		t.Helper()
		f.refresh(t)
		now := time.Now().UTC().Truncate(time.Microsecond)
		in := audit.OperationIntent{ID: custodyID(), RootID: root, TraceID: custodyID(), Name: tool, InputFormat: "context-query-input/v1", MACVersion: "comparison-fixture/v1", AccountVersion: f.base.input.AccountVersion, Actor: principal, PrincipalDigest: artifact.Digest{41}, InputDigest: artifact.Digest{42}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Duration(f.audit.Normal.RetainedSeconds) * time.Second)}
		if err := auditor.Begin(ctx, in); err != nil {
			t.Fatal("pair invocation audit", err)
		}
		return value.ContextQueryRequest{Call: value.ContextQueryCall{ID: in.ID, RootID: root, Tool: tool, InputFormat: in.InputFormat, MACVersion: in.MACVersion, InputDigest: in.InputDigest, PrincipalDigest: in.PrincipalDigest, Principal: principal, StartedAt: in.CreatedAt, Until: in.RequestUntil, WriteUntil: in.WriteUntil}, OwnerID: custodyID(), HubProcessEpoch: custodyID()}, in
	}
	request, intent := invocation("compare_profiles")
	a := authority()
	plans, e := f.current.ContextComparisonPlans(ctx, a)
	if e != nil {
		t.Fatal("pair plan read", e)
	}
	q, e := value.NewProfileComparisonQuery(custodyID(), request.Call.ID, custodyID(), a, plans[0], plans[1], time.Now())
	if e != nil {
		t.Fatal(e)
	}
	admission, e := ledger.AdmitQuery(ctx, q, request, a)
	if e != nil || !admission.Fresh {
		t.Fatal("same-artifact paired admission", e)
	}
	replay, e := ledger.AdmitQuery(ctx, q, request, a)
	if e != nil || replay.Fresh || !replay.Query.Equal(q) {
		t.Fatal("paired replay refilled", e)
	}
	charge := func() (int64, int64, int64) {
		t.Helper()
		var total, account, allocation int64
		if err := admin.QueryRow(ctx, "SELECT b.allocated,p.allocated,a.allocated FROM context_query_backing b JOIN context_query_principal p ON p.root_id=b.root_id JOIN context_query_allocation a ON a.id=$2 WHERE b.root_id=$1", root, q.Plan.AllocationID).Scan(&total, &account, &allocation); err != nil {
			t.Fatal(err)
		}
		return total, account, allocation
	}
	if total, account, allocation := charge(); total != 20 || account != 20 || allocation != 20 {
		t.Fatal("same workload did not charge20 once", total, account, allocation)
	}
	for _, kind := range []string{"baseline-processing", "baseline-retention"} {
		changed := a
		child := *a.Baseline
		changed.Baseline = &child
		if kind == "baseline-processing" {
			child.Environment.Processing.StateDigest[0]++
		} else {
			child.Retention.Sources[0].SnapshotDigest[0]++
		}
		if err := ledger.PermitQuery(ctx, q, request, changed); err == nil {
			t.Fatal("second source current SQL fence omitted", kind)
		}
	}
	workers, e := postgres.NewProjectionWorkers(ledger, f.workerProfile)
	if e != nil {
		t.Fatal(e)
	}
	state, e := workers.ReserveProjectionWorker(ctx, q, request, a)
	if e != nil || !state.Intent.Valid() {
		t.Fatal("pair physical worker reservation", e)
	}
	ownership.worker = value.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), Certificate: artifact.Digest{51}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	if _, e = admin.Exec(ctx, "INSERT INTO context_query_worker(query_id,worker_id,binding,proof) VALUES($1,$2,$3,$4)", q.ID, q.WorkerID, raw(ownership.worker), raw(map[string]string{"Qualification": "synthetic C14 SQL fixture only"})); e != nil {
		t.Fatal(e)
	}
	a = authority()
	batchAdmission, e := ledger.BeginReadBatch(ctx, q, request, ownership.worker, custodyID(), a)
	if e != nil || !batchAdmission.Fresh {
		t.Fatal("pair batch", e)
	}
	batch := batchAdmission.Batch
	if start, err := ledger.ClaimReadBatch(ctx, batch, a); err != nil || !start.Fresh {
		t.Fatal("pair claim", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := authorization.NativeOperation{Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing, Reference: authorization.NativeReference{InstallationID: q.Plan.InstallationID, QueryID: q.ID, WorkerID: q.WorkerID, OperationID: batch.ID, Fence: batch.Generation}, Kind: authorization.NativeProjection, HubPodUID: custodyID(), HubProcessEpoch: request.HubProcessEpoch, WorkerPodUID: ownership.worker.PodUID, WorkerPublicKey: artifact.Digest{52}, SourceVersion: q.Scope.Version, ParentID: batch.ID, Generation: batch.Generation, StartedAt: now, Until: identity.Earlier(batch.Until, a.ValidUntil), Baseline: authorization.NativeProjectionSource{Path: a.Baseline.Environment.Path.AcquisitionPath(), Processing: a.Baseline.Environment.Processing, SourceVersion: q.Scope.Comparison.Baseline.Version}}
	if !op.CurrentValid(now) {
		t.Fatal("synthetic native operation invalid")
	}
	if _, e = admin.Exec(ctx, "UPDATE context_query_batch SET native_operation=$2,native_authority=$3 WHERE id=$1", batch.ID, raw(op), raw(a)); e != nil {
		t.Fatal("exact pair native pins", e)
	}
	ids, e := value.ProfileComparisonKeyChildIDs(batch.ID)
	if e != nil {
		t.Fatal(e)
	}
	children := [2]value.ContextProjectionComparisonKeyChild{}
	for ordinal := range children {
		children[ordinal] = value.ContextProjectionComparisonKeyChild{ID: ids[ordinal], QueryID: q.ID, BatchID: batch.ID, WorkerID: q.WorkerID, ProcessEpoch: batch.Worker.ProcessEpoch, SourceOrdinal: ordinal, SourceVersion: q.Scope.Version, AuthorityDigest: a.DecisionDigest, PublicKey: op.WorkerPublicKey, Certificate: batch.Worker.Certificate, Scope: authorization.KeyScope{InstallationID: q.Plan.InstallationID, Purpose: "artifact", KeyID: "evidence"}, CreatedAt: now, Until: op.Until}
		if !children[ordinal].Valid(q, batch, a, now) {
			t.Fatal("compact SQL fixture child invalid")
		}
	}
	// A single child cannot commit; no second source is inferred or refilled.
	if _, e = admin.Exec(ctx, "INSERT INTO context_query_key_binding(child_id,batch_id,query_id,source_ordinal,binding) VALUES($1,$2,$3,0,$4)", ids[0], batch.ID, q.ID, raw(children[0])); e == nil {
		t.Fatal("partial pair child committed")
	}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for ordinal := range children {
		if _, e = tx.Exec(ctx, "INSERT INTO context_query_key_binding(child_id,batch_id,query_id,source_ordinal,binding) VALUES($1,$2,$3,$4,$5)", ids[ordinal], batch.ID, q.ID, ordinal, raw(children[ordinal])); e != nil {
			_ = tx.Rollback(ctx)
			t.Fatal("atomic pair child insert", e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal("two immutable children commit", e)
	}
	for _, id := range ids {
		for _, bits := range []int{1, 3, 7} {
			if _, e = slots.Exec(ctx, "UPDATE context_query_key_binding SET used_roles=$2 WHERE child_id=$1", id, bits); e != nil {
				t.Fatal("independent SQL role slot", e)
			}
		}
		for _, bits := range []int{0, 3, 7} {
			if _, e = slots.Exec(ctx, "UPDATE context_query_key_binding SET used_roles=$2 WHERE child_id=$1", id, bits); e == nil {
				t.Fatal("SQL role refill/replay accepted")
			}
		}
	}
	for _, statement := range []string{"UPDATE context_query_key_binding SET source_ordinal=1-source_ordinal WHERE batch_id=$1", "UPDATE context_query_key_binding SET binding=jsonb_set(binding,'{SourceOrdinal}',to_jsonb(1-source_ordinal)) WHERE batch_id=$1"} {
		if _, e = admin.Exec(ctx, statement, batch.ID); e == nil {
			t.Fatal("ordinal swap accepted")
		}
	}
	var spent int
	if e = admin.QueryRow(ctx, "SELECT count(*) FROM context_query_key_binding WHERE batch_id=$1 AND used_roles=7", batch.ID).Scan(&spent); e != nil || spent != 2 {
		t.Fatal("six SQL slots not independently spent", spent, e)
	}
	if _, e = admin.Exec(ctx, "UPDATE context_query_batch SET native_closed=true WHERE id=$1", batch.ID); e != nil {
		t.Fatal("native SQL close", e)
	}
	outcome := audit.OperationOutcome{Intent: intent, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: artifact.Digest{61}, OutputBytes: 12, MetadataUntil: intent.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if e = auditor.Finish(ctx, outcome); e != nil {
		t.Fatal("paired outcome ack", e)
	}
	if e = ledger.CompleteReadBatch(ctx, batch, querySQLClosed{batch}); e != nil {
		t.Fatal("paired batch closes only after outcome", e)
	}
	qualifyComparisonCrossAllocationSQL(t, f, q, authority, invocation)
	refuseRetainedComparisonDowngrade(t, f)
	t.Log("same-artifact real C3/C7/ledger:20 units once, one batch, two child identities/six SQL role spends; synthetic C14 ownership, not mTLS consumption or installed qualification")
}

func refuseRetainedComparisonDowngrade(t *testing.T, f *queryLedgerFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.base.admin.Config().ConnConfig)
	defer db.Close()
	provider, e := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if e != nil {
		t.Fatal(e)
	}
	var before, after []byte
	snapshot := func(out *[]byte) {
		if err := f.base.admin.QueryRow(f.base.ctx, "SELECT jsonb_build_object('q',(SELECT jsonb_agg(to_jsonb(q) ORDER BY id) FROM context_query q),'a',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM context_query_allocation a),'b',(SELECT jsonb_agg(to_jsonb(b) ORDER BY root_id) FROM context_query_backing b),'k',(SELECT jsonb_agg(to_jsonb(k) ORDER BY child_id) FROM context_query_key_binding k))").Scan(out); err != nil {
			t.Fatal(err)
		}
	}
	snapshot(&before)
	if _, e = provider.DownTo(f.base.ctx, 132); e == nil || !strings.Contains(e.Error(), "comparison history retained") {
		t.Fatal("retained pair rollback allowed", e)
	}
	head, e := provider.GetDBVersion(f.base.ctx)
	snapshot(&after)
	if e != nil || head != 133 || string(before) != string(after) {
		t.Fatal("refused pair downgrade changed spend/state", head, e)
	}
}

// Distinct-workload coverage below uses a second ACTUAL capacity enrollment
// and a synthetic second source route, inserted through the real SQL guard.
// It qualifies atomic accounting/worker filters, not second-source publication
// or C3 eligibility. The Go current fence must refuse that unpublished route.
func qualifyComparisonCrossAllocationSQL(t *testing.T, f *queryLedgerFixture, original value.ContextQuery, refresh func() value.ContextProjectionAuthority, invocation func(string) (value.ContextQueryRequest, audit.OperationIntent)) {
	t.Helper()
	ctx, admin := f.base.ctx, f.base.admin
	raw := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	coordinator := capacityapp.EnrollmentCoordinator{Store: f.base.enrollments, Capture: f.base.captureEnrollments, Accounts: f.base.accounts, Now: time.Now}
	if _, e := coordinator.Reconcile(ctx, f.base.workloadObservation(t, 1)); e != nil {
		t.Fatal("second real capacity enrollment", e)
	}
	var cluster, namespace, workload string
	if e := admin.QueryRow(ctx, "SELECT cluster_id::text,namespace_uid,workload_uid FROM context_query_allocation WHERE root_id=$1 AND id<>$2", original.Scope.RootID, original.Plan.AllocationID).Scan(&cluster, &namespace, &workload); e != nil {
		t.Fatal("second actual query allocation", e)
	}
	synthetic := func() value.ContextProjectionAuthority {
		a := refresh()
		b := *a.Baseline
		a.Scope.Comparison.Baseline = value.ProfileComparisonBaseline{CaseID: custodyID(), ArtifactID: custodyID(), CaptureID: custodyID(), ClusterID: cluster, NamespaceUID: namespace, WorkloadUID: workload, PodUID: "synthetic-unpublished-second-pod", Version: artifact.Digest{73}}
		b.Scope, _ = a.Scope.BaselineScope()
		b.Environment.Location.ClusterID = cluster
		b.Environment.Location.ArtifactID = b.Scope.ArtifactID
		b.Environment.Processing.Location = b.Environment.Location
		b.Environment.Processing.CaptureID = b.Scope.CaptureID
		b.Environment.Path.TargetClusterID = cluster
		b.Retention.ClusterID, b.Retention.NamespaceUID, b.Retention.WorkloadUID, b.Retention.PodUID = cluster, namespace, workload, b.Scope.PodUID
		if b.Retention.SourceCount == 2 {
			b.Retention.Sources[1].ClusterID = cluster
		}
		a.Baseline = &b
		if !a.Valid(time.Now()) {
			t.Fatal("explicit synthetic second route DTO invalid")
		}
		return a
	}
	insert := func(q value.ContextQuery, r value.ContextQueryRequest) error {
		var baseline any
		if q.BaselinePlan.AllocationID != "" {
			baseline = q.BaselinePlan.AllocationID
		}
		_, e := admin.Exec(ctx, `INSERT INTO context_query(id,root_id,allocation_id,account_id,principal_key,actor,query,initial_request,operation_id,worker_id,created_at,deadline,cleanup_until,retire_by,issuer_epoch,postmaster_at,database_oid,baseline_allocation_id)
 SELECT $1,$2,$3,$4,p.principal_key,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),$15 FROM context_query_principal p WHERE p.id=$4 AND p.root_id=$2`, q.ID, q.Scope.RootID, q.Plan.AllocationID, q.Plan.AccountID, raw(q.Scope.Principal), raw(q), raw(r), q.OperationID, q.WorkerID, q.CreatedAt, q.Deadline, q.CleanupUntil, q.Plan.RetireBy, q.RecoveryIssuerEpoch, baseline)
		return e
	}
	pairRequest, _ := invocation("compare_profiles")
	a := synthetic()
	plans, e := f.current.ContextComparisonPlans(ctx, a)
	if e != nil {
		t.Fatal("two protected workload plans", e)
	}
	q, e := value.NewProfileComparisonQuery(custodyID(), pairRequest.Call.ID, custodyID(), a, plans[0], plans[1], time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e = insert(q, pairRequest); e != nil {
		t.Fatal("cross-allocation SQL admission", e)
	}
	snapshot := func() (int64, int64, int64, int64) {
		var total, principal, first, second int64
		e := admin.QueryRow(ctx, `SELECT b.allocated,p.allocated,i.allocated,s.allocated FROM context_query_backing b JOIN context_query_principal p ON p.id=$2 JOIN context_query_allocation i ON i.id=$3 JOIN context_query_allocation s ON s.id=$4 WHERE b.root_id=$1`, q.Scope.RootID, q.Plan.AccountID, q.Plan.AllocationID, q.BaselinePlan.AllocationID).Scan(&total, &principal, &first, &second)
		if e != nil {
			t.Fatal(e)
		}
		return total, principal, first, second
	}
	if total, principal, first, second := snapshot(); total != 40 || principal != 40 || first != 30 || second != 10 {
		t.Fatal("cross workload not10+10/root20", total, principal, first, second)
	}
	// One worker with two allocation references is counted only once in the
	// global/principal totals and once in each workload's separate ceiling.
	intent := value.ContextProjectionWorkerIntent{Query: q, Worker: authorization.AcquisitionWorkerIntent{ID: q.WorkerID, Parent: authorization.AcquisitionParent{Purpose: authorization.AcquisitionProjection, ID: q.ID}, Profile: f.workerProfile, CreatedAt: q.CreatedAt, RunUntil: q.WorkerUntil}}
	if !intent.Valid() {
		t.Fatal("synthetic cross worker DTO invalid")
	}
	var principalKey []byte
	if e = admin.QueryRow(ctx, "SELECT principal_key FROM context_query_principal WHERE id=$1", q.Plan.AccountID).Scan(&principalKey); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.Exec(ctx, `INSERT INTO download_worker(id,query_id,root_id,installation_id,query_allocation_id,baseline_query_allocation_id,principal_key,generation,intent_json,run_until) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9)`, q.WorkerID, q.ID, q.Scope.RootID, q.Plan.InstallationID, q.Plan.AllocationID, q.BaselinePlan.AllocationID, principalKey, raw(intent), q.WorkerUntil); e != nil {
		t.Fatal("two-allocation worker row", e)
	}
	for i, p := range []value.ContextQueryPlan{q.Plan, q.BaselinePlan} {
		counts, err := custodydb.New(admin).AcquisitionWorkerCapacity(ctx, custodydb.AcquisitionWorkerCapacityParams{InstallationID: capacityProjectionUUID(t, q.Plan.InstallationID), ClusterID: capacityProjectionUUID(t, p.ClusterID), NamespaceUid: p.NamespaceUID, WorkloadUid: p.WorkloadUID, PrincipalKey: principalKey})
		want := int64(2)
		if i == 1 {
			want = 1
		}
		if err != nil || counts.Total != 2 || counts.Principal != 2 || counts.Workload != want {
			t.Fatal("pair worker not counted against both distinct workloads", counts, want, err)
		}
	}
	// Fill only the second allocation with separately audited10-unit summary
	// rows. These synthetic-source SQL rows do not acquire or expose evidence.
	for i := 0; i < 3; i++ {
		r, _ := invocation("get_profile_summary")
		fresh := synthetic()
		child := *fresh.Baseline
		p, err := f.current.ContextQueryPlan(ctx, child)
		if err != nil {
			t.Fatal(err)
		}
		single, err := value.NewContextQuery(custodyID(), r.Call.ID, custodyID(), child, p, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err = insert(single, r); err != nil {
			t.Fatal("fill second workload independently", err)
		}
	}
	total, principal, first, second := snapshot()
	if total != 70 || principal != 70 || first != 30 || second != 40 {
		t.Fatal("second-budget setup mismatch", total, principal, first, second)
	}
	r, _ := invocation("compare_profiles")
	fresh := synthetic()
	nextPlans, err := f.current.ContextComparisonPlans(ctx, fresh)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := value.NewProfileComparisonQuery(custodyID(), r.Call.ID, custodyID(), fresh, nextPlans[0], nextPlans[1], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = insert(denied, r)
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != "23514" {
		t.Fatal("full second budget did not refuse", err)
	}
	afterTotal, afterPrincipal, afterFirst, afterSecond := snapshot()
	if afterTotal != total || afterPrincipal != principal || afterFirst != first || afterSecond != second {
		t.Fatal("failed second budget partly charged first/root/principal", afterTotal, afterPrincipal, afterFirst, afterSecond)
	}
	t.Log("real133 SQL atomicity: distinct allocations10+10; root/principal20 once; failed second budget preserves all spend; worker counts once globally and against both workloads; second route explicitly synthetic/unpublished")
}
