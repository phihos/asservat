package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The declared report/profile and four native deployment guards are synthetic.
// This verifies actual original installation/role/source/phase-3 provenance and
// SQL69 accounting. It does NOT qualify worker/provider resource enforcement.
func TestContextQueryCapacityWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyContextQueryCapacitySQL)
}

type queryCapacitySyntheticGuard struct{}

func (queryCapacitySyntheticGuard) WithCurrentQueryDeployment(ctx context.Context, _ app.ContextQueryQualification, _ app.QueryDeploymentPin, next func(context.Context) error) error {
	return next(ctx)
}

func syntheticQueryCapacityQualification(t *testing.T, f *capacitySQLFixture) {
	t.Helper()
	root, cluster := f.qualification.RootBacking.RootID, f.template.ClusterID
	rev := identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{41}}
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: custodyID(), TargetClusterID: cluster, StoreID: f.qualification.Backends[0].EvidenceStoreID, StorageRegion: "local", AcquisitionClusterID: cluster, AcquisitionRegion: "local", ConnectorClusterID: cluster, ConnectorRegion: "local", HubClusterID: cluster, HubRegion: "local", WorkerConfiguration: rev, HubConfiguration: rev}
	p := value.ContextQueryResourceProfile{ID: custodyID(), Source: rev, Qualification: rev, Path: path, Lifetime: 10 * time.Second, PollLimit: 4, ControlTransitionLimit: 32,
		Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
		Cost:   value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 8 << 20, StructuredBytes: 48 << 10, WireBytes: 128 << 10, UnwrapAttempts: 6, ProviderRequests: 100, AuthenticationRequests: 100, SigningAttempts: 2, AuditObjects: 13, SQLRows: 47, SQLBytes: 4 << 20, WALBytes: 64 << 20, BackupBytes: 8 << 20}}
	q := app.ContextQueryQualification{Format: app.ContextQueryQualificationFormat, CapacityID: custodyID(), Profile: p, RootQueries: 2, PrincipalQueries: 1, PrincipalAccounts: 2, WorkloadAccounts: 1, WorkloadQueries: 2, SourceTransitionLimit: 6, Admission: 60 * time.Second, PolicyRevision: rev, PermittedRegions: []string{"local"}, Clients: []value.ContextProjectionClient{{Issuer: "https://id.example.test", ID: "console", Kind: identity.Human, Purposes: []string{"diagnostics"}}},
		History: app.QueryHistoryQualification{Layout: app.ContextQueryHistoryLayout, Revision: rev, FixedBytes: 1 << 20, PrincipalBytes: 4096, AllocationBytes: 4096, RowBytes: 4096, FixedQueryRows: 10, InvocationRows: 1, ControlRows: 1, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2, AuditCipherBytes: 64 << 10, AuthenticationPerCall: 1, ProviderPerCall: 1, AuthenticationPerControl: 1, ProviderPerControl: 1, AuthenticationPerSource: 1, ProviderPerSource: 1, BackupHorizon: time.Hour, RetirementCleanup: time.Minute}}
	b, _ := json.Marshal(p.Cost)
	var costs map[string]int64
	if json.Unmarshal(b, &costs) != nil {
		t.Fatal("synthetic cost vector")
	}
	for k, n := range costs {
		costs[k] = n * 2
	}
	costs["ProviderRequests"] += 7
	costs["AuthenticationRequests"] += 7
	costs["SQLBytes"] = 12 << 20
	costs["BackupBytes"] = 24 << 20
	costs["WALBytes"] = 160 << 20
	b, _ = json.Marshal(costs)
	if json.Unmarshal(b, &q.Envelope.ContextQueryCost) != nil {
		t.Fatal("synthetic cost vector")
	}
	q.Envelope.QueryProcessEnvelope = app.QueryProcessEnvelope{CPUMilli: 200, MemoryBytes: 128 << 20, EphemeralStorageBytes: 8 << 20, WorkerTransientBytes: 16 << 20, HubTransientBytes: 256 << 10, ProviderConcurrency: 2, AuthenticationConcurrency: 2}
	pin := func(role string) app.QueryDeploymentPin {
		return app.QueryDeploymentPin{Role: role, ClusterID: cluster, NamespaceUID: f.template.ControlNamespace.UID, WorkloadUID: role + "-" + root, Image: "synthetic-only@sha256:" + strings.Repeat("a", 64), Configuration: rev, ProtectionDigest: artifact.Digest{42}, EnforcedLimitsDigest: artifact.Digest{43}, Limits: q.Envelope.QueryProcessEnvelope}
	}
	b, _ = json.Marshal(p)
	q.Native = app.QueryNativeQualification{Revision: rev, Format: "context-query-native-qualification/v1", RunID: "synthetic-sql-component-only", ReportDigest: artifact.Digest{44}, SourceTree: artifact.Digest{45}, ProfileDigest: sha256.Sum256(b), Worker: pin("query-worker"), Hub: pin("hub"), KeyService: pin("query-key-service"), Provider: pin("query-provider"), Combined: q.Envelope.QueryProcessEnvelope}
	q.Native.Combined = app.QueryProcessEnvelope{CPUMilli: q.Envelope.CPUMilli * 4, MemoryBytes: q.Envelope.MemoryBytes * 4, EphemeralStorageBytes: q.Envelope.EphemeralStorageBytes * 4, WorkerTransientBytes: q.Envelope.WorkerTransientBytes * 4, HubTransientBytes: q.Envelope.HubTransientBytes * 4, ProviderConcurrency: q.Envelope.ProviderConcurrency * 4, AuthenticationConcurrency: q.Envelope.AuthenticationConcurrency * 4}
	q.Envelope.QueryProcessEnvelope = q.Native.Combined
	f.qualification.ContextQuery = &q
	if !f.qualification.Valid() {
		t.Fatal("synthetic query qualification structurally invalid")
	}
}

func qualifyContextQueryCapacitySQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) { syntheticQueryCapacityQualification(t, f) })
	qualificationBody, _ := json.Marshal(f.qualification.ContextQuery)
	baseBody, _ := json.Marshal(f.qualification.RootBacking)
	for _, mode := range []string{"original", "legacy-history", "missing-limits", "duplicate-deployment", "short-worker", "short-rows", "short-audits", "unknown-profile-field"} {
		var candidate map[string]any
		if e := json.Unmarshal(qualificationBody, &candidate); e != nil {
			t.Fatal(e)
		}
		profile := candidate["Profile"].(map[string]any)
		switch mode {
		case "legacy-history":
			candidate["History"].(map[string]any)["Layout"] = "context-query-history/v1"
		case "missing-limits":
			delete(candidate["Native"].(map[string]any)["Provider"].(map[string]any), "Limits")
		case "duplicate-deployment":
			native := candidate["Native"].(map[string]any)
			native["Provider"].(map[string]any)["WorkloadUID"] = native["KeyService"].(map[string]any)["WorkloadUID"]
		case "short-worker":
			candidate["Native"].(map[string]any)["Worker"].(map[string]any)["Limits"].(map[string]any)["CPUMilli"] = 1
		case "short-rows":
			profile["Cost"].(map[string]any)["SQLRows"] = 12
		case "short-audits":
			profile["Cost"].(map[string]any)["AuditObjects"] = 10
		case "unknown-profile-field":
			profile["Other"] = true
		}
		body, _ := json.Marshal(candidate)
		var valid bool
		if e := admin.QueryRow(ctx, "SELECT context_query_qualification_valid($1::jsonb,$2::jsonb)", body, baseBody).Scan(&valid); e != nil || valid != (mode == "original") {
			t.Fatal("SQL qualification validation", mode, e)
		}
	}
	if _, e := f.producer.InitializeCapacity(ctx, f.input, f.protection); e != nil {
		t.Fatal("actual original query qualification setup", e)
	}
	f.open(t)
	o := f.rootObservation(t)
	root, e := f.roots.ReserveCapacityRoot(ctx, o)
	if e != nil {
		t.Fatal("reserve base root", e)
	}
	root, e = f.captureRoots.BackCapacityRoot(ctx, o, root)
	if e != nil {
		t.Fatal("capture backing", e)
	}
	root, e = f.roots.PublishCapacityRoot(ctx, o, root)
	if e != nil || !root.AdmissionReady(time.Now()) {
		t.Fatal("publish base root", e)
	}
	coordinator := app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
	observation := f.workloadObservation(t, 0)
	enrolled, e := coordinator.Reconcile(ctx, observation)
	if e != nil {
		t.Fatal("actual protected workload", e)
	}
	// These narrow grants are fixture-only. Production role layout/bootstrap is
	// deliberately unchanged by the inert query-capacity component.
	writerName := pgx.Identifier{f.roles["capacity"].Config().ConnConfig.User}.Sanitize()
	readerName := pgx.Identifier{f.roles["capacity-profile-read"].Config().ConnConfig.User}.Sanitize()
	if _, e = admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION read_context_query_capacity_source(uuid,jsonb),read_context_query_capacity_plan(uuid,uuid,uuid,text,text,jsonb,bytea,uuid) TO "+readerName+"; GRANT EXECUTE ON FUNCTION accept_context_query_capacity(uuid,jsonb,jsonb),allocate_context_query_capacity(uuid,uuid,uuid,text,text,uuid),suspend_context_query_capacity(uuid,timestamptz) TO "+writerName); e != nil {
		t.Fatal("fixture purpose grants", e)
	}
	reads, e := postgres.NewContextQueryCapacityReads(ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	writes, e := postgres.NewContextQueryCapacityProducer(ctx, f.roles["capacity"], f.input.PermissionRootID, f.input.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	guard := queryCapacitySyntheticGuard{}
	current := app.ProtectedContextQueryCapacity{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, Store: reads, Recovery: f.source, Deployments: app.QueryDeploymentGuards{Worker: guard, Hub: guard, KeyService: guard, Provider: guard}, Now: time.Now, NewID: custodyID}
	producer := app.ProtectedContextQueryProducer{Current: current, Writer: writes}
	refresh := func() {
		f.fresh(t)
		fresh := f.workloadObservation(t, 0)
		if e := f.enrollments.RefreshCapacityEnrollment(ctx, fresh, enrolled); e != nil {
			t.Fatal("original workload observation", e)
		}
	}
	// Consumer probes run through the separate runtime credential. The fixture
	// administrator supplies neither a query anchor nor a positive guard result.
	runtimeConfig, e := pgxpool.ParseConfig("postgres://context_query_runtime:synthetic-context-query@" + address + "/custody_test?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	runtimeConfig.ConnConfig.TLSConfig = tlsConfig
	runtimeConfig.ConnConfig.Fallbacks = nil
	runtimeConfig.MaxConns = 1
	runtime, e := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	probe := func(statement, argument string, want bool) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var got bool
		if err := runtime.QueryRow(bounded, statement, current.RootID, argument).Scan(&got); err != nil || got != want {
			t.Fatalf("scoped capacity consumer: got %v, want %v: %v", got, want, err)
		}
	}
	const anchorProbe = "SELECT lock_context_query_capacity($1,$2)"
	const allocationProbe = "SELECT context_query_capacity_allocation_current($1,$2)"
	probe(anchorProbe, custodyID(), false)
	refresh()
	key := app.WorkloadCapacityKey{RootID: current.RootID, ClusterID: scope.ClusterID, NamespaceUID: f.namespace.UID, WorkloadUID: f.workloads[0].UID}
	if e = producer.Reconcile(ctx, &key); e != nil {
		t.Fatal("query original acceptance", e)
	}
	policy, e := current.ContextProjectionPolicy(ctx)
	if e != nil || !policy.Valid(time.Now()) || policy.Path != f.qualification.ContextQuery.Profile.Path {
		t.Fatal("current accepted query policy", e)
	}
	var original []byte
	var accepted string
	var observations int64
	if e = admin.QueryRow(ctx, `SELECT plan,acceptance_id::text,observations FROM context_query_capacity WHERE root_id=$1`, current.RootID).Scan(&original, &accepted, &observations); e != nil || observations != 1 {
		t.Fatal("accepted query reservation missing", e)
	}
	var allocationID string
	if e = admin.QueryRow(ctx, "SELECT id::text FROM context_query_allocation WHERE root_id=$1", current.RootID).Scan(&allocationID); e != nil {
		t.Fatal("accepted allocation missing", e)
	}
	probe(anchorProbe, accepted, true)
	probe(anchorProbe, custodyID(), false)
	probe(allocationProbe, allocationID, true)
	probe(allocationProbe, custodyID(), false)
	var baseObjects, baseBytes int64
	if e = admin.QueryRow(ctx, `SELECT backed_system_bytes,backed_system_objects FROM capacity_pool WHERE root_id=$1 AND source_uid=$2`, current.RootID, f.qualification.RootBacking.SystemPoolUID).Scan(&baseBytes, &baseObjects); e != nil {
		t.Fatal(e)
	}
	refresh()
	if e = producer.Reconcile(ctx, &key); e != nil {
		t.Fatal("exact acceptance replay", e)
	}
	var same bool
	if e = admin.QueryRow(ctx, `SELECT plan=$2::jsonb AND acceptance_id=$3::uuid AND observations=2 FROM context_query_capacity WHERE root_id=$1`, current.RootID, original, accepted).Scan(&same); e != nil || !same {
		t.Fatal("replay renewed original reservation", e)
	}
	// Missing independent deployment guard cannot write another observation.
	broken := producer
	broken.Current.Deployments.Provider = nil
	if e = broken.Reconcile(ctx, nil); e == nil {
		t.Fatal("worker guard implied provider qualification")
	}
	if e = admin.QueryRow(ctx, `SELECT observations=2 FROM context_query_capacity WHERE root_id=$1`, current.RootID).Scan(&same); e != nil || !same {
		t.Fatal("failed guard spent or accepted backing", e)
	}
	if e = writes.SuspendQueryCapacity(ctx, time.Now().UTC().Truncate(time.Microsecond)); e != nil {
		t.Fatal("persist negative", e)
	}
	if _, e = current.ContextProjectionPolicy(ctx); e == nil {
		t.Fatal("suspended capacity disclosed a policy")
	}
	probe(allocationProbe, allocationID, false)
	refresh()
	if e = producer.Reconcile(ctx, nil); e != nil {
		t.Fatal("new current proof after negative", e)
	}
	for i := 0; i < 2; i++ {
		refresh()
		if e = producer.Reconcile(ctx, nil); e != nil {
			t.Fatal("finite observation", e)
		}
	}
	refresh()
	if e = producer.Reconcile(ctx, nil); e == nil {
		t.Fatal("observation allowance replenished")
	}
	if e = writes.SuspendQueryCapacity(ctx, time.Now().UTC().Truncate(time.Microsecond)); e != nil {
		t.Fatal("prepaid terminal negative unavailable", e)
	}
	if e = admin.QueryRow(ctx, `SELECT a.plan=$2::jsonb AND a.observations=7 AND b.suspended AND b.allocations=1 AND b.allocated=0 FROM context_query_capacity a JOIN context_query_backing b USING(root_id) WHERE a.root_id=$1`, current.RootID, original).Scan(&same); e != nil || !same {
		t.Fatal("terminal source state lost original obligations", e)
	}
	var bytesAfter, objectsAfter int64
	if e = admin.QueryRow(ctx, `SELECT backed_system_bytes,backed_system_objects FROM capacity_pool WHERE root_id=$1 AND source_uid=$2`, current.RootID, f.qualification.RootBacking.SystemPoolUID).Scan(&bytesAfter, &objectsAfter); e != nil || bytesAfter != baseBytes || objectsAfter != baseObjects {
		t.Fatal("additive reservation modified original base graph", e)
	}
	t.Log("actual protected root and additive finite query reservation passed; report, resource measurements and native deployment guards are synthetic; runtime grants unchanged")
}
