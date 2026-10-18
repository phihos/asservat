package integration

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This owns a pristine installation, its real protected capacity root and
// additive query reservation. Run separately from other pristine-root cases.
// Native resource measurements/deployment guards, human identity and C14
// ownership remain explicit synthetic inputs; this is SQL/S3 qualification.
func TestContextQueryLedgerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, qualifyProtectedContextQueryLedger)
}

func TestContextQueryLedgerOriginalQualification(t *testing.T) {
	q, source := capacityNativeQualification(t, custodyID(), custodyID(), custodyID(), custodyID(), "fixture-accounts-v1")
	f := &capacitySQLFixture{qualification: q, template: source}
	queryLedgerQualification(t, f)
	pool, err := app.CompileProtectedPoolPlan(source, source.Pools[0].Resource.Name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.CompileQualifiedRootBacking(f.qualification, pool); err != nil {
		t.Fatal("complete original normal-audit and query reservation", err)
	}
}

type queryLedgerFixture struct {
	base      *capacitySQLFixture
	enrolled  app.Enrollment
	current   app.ProtectedContextQueryCapacity
	producer  app.ProtectedContextQueryProducer
	key       app.WorkloadCapacityKey
	scenario  captureAdmissionScenario
	published artifact.PublishedContext
	audit     audit.AcceptedCapacityAuditProfiles
}

func (f *queryLedgerFixture) currentProfile() value.ContextQueryResourceProfile {
	return f.base.qualification.ContextQuery.Profile
}

// New source observations precede new requests. They never modify an admitted
// query, batch or its original deadlines. Each producer reconciliation spends
// the finite allowance accepted in the original installation qualification.
func (f *queryLedgerFixture) refresh(t *testing.T) {
	t.Helper()
	o := f.base.workloadObservation(t, 0)
	if err := f.base.enrollments.RefreshCapacityEnrollment(f.base.ctx, o, f.enrolled); err != nil {
		t.Fatal("current managed workload", err)
	}
	if err := f.producer.Reconcile(f.base.ctx, &f.key); err != nil {
		t.Fatal("current protected query backing", err)
	}
}

func queryLedgerQualification(t *testing.T, f *capacitySQLFixture) {
	t.Helper()
	syntheticQueryCapacityQualification(t, f)
	q := f.qualification.ContextQuery
	q.Profile.Lifetime = 60 * time.Second
	q.PrincipalQueries = 2
	q.SourceTransitionLimit = 64
	q.Envelope.ProviderRequests += 64 - 6
	q.Envelope.AuthenticationRequests += 64 - 6
	q.Clients = append(q.Clients, value.ContextProjectionClient{Issuer: "https://id.example.test", ID: "fixture-other-client", Kind: q.Clients[0].Kind, Purposes: []string{"diagnostics"}})
	body, err := json.Marshal(q.Profile)
	if err != nil {
		t.Fatal(err)
	}
	q.Native.ProfileDigest = sha256.Sum256(body)
	// Cover the original 60-second evidence and its deletion allowance from
	// before capture preparation. Query admission remains its original 60s.
	f.qualification.RootBacking.AdmissionSeconds = 120
	// Reserve every audit slot before original installation; no post-install
	// configuration CAS or synthetic replacement of the accepted normal pool.
	normal := &f.qualification.RootBacking.Normal
	normal.RecordsPerAccount = 32
	normal.Policy.MetadataSlots = normal.Accounts * normal.RecordsPerAccount
	b, w := normal.Policy.History.SlotBacking(normal.Policy.MaxPurgeLeases)
	normal.Policy.BackupReservedBytes = b * normal.Policy.MetadataSlots
	normal.Policy.WALReservedBytes = w * normal.Policy.MetadataSlots
	if !f.qualification.Valid() {
		t.Fatal("original finite ledger qualification invalid")
	}
}

func qualifyProtectedContextQueryLedger(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) { queryLedgerQualification(t, f) })
	// Pools opened by this owned extension close on function return. The base
	// fixture's pools and source loop close with this sole top-level fixture.
	originalPool := f.fixturePool
	var pools []*pgxpool.Pool
	f.fixturePool = func(role, password string) *pgxpool.Pool {
		p := originalPool(role, password)
		pools = append(pools, p)
		return p
	}
	defer func() {
		for _, p := range pools {
			p.Close()
		}
	}()
	if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err != nil {
		t.Fatal("actual original ledger qualification setup", err)
	}
	f.open(t)
	o := f.rootObservation(t)
	root, err := f.roots.ReserveCapacityRoot(ctx, o)
	if err != nil {
		t.Fatal("reserve original capacity root", err)
	}
	root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
	if err != nil {
		t.Fatal("back original capture root", err)
	}
	root, err = f.roots.PublishCapacityRoot(ctx, o, root)
	if err != nil || !root.AdmissionReady(time.Now()) {
		t.Fatal("publish actual capacity root", err)
	}
	coordinator := app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}
	enrolled, err := coordinator.Reconcile(ctx, f.workloadObservation(t, 0))
	if err != nil {
		t.Fatal("actual managed workload", err)
	}
	writer := pgx.Identifier{f.roles["capacity"].Config().ConnConfig.User}.Sanitize()
	reader := pgx.Identifier{f.roles["capacity-profile-read"].Config().ConnConfig.User}.Sanitize()
	if _, err = admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION read_context_query_capacity_source(uuid,jsonb),read_context_query_capacity_plan(uuid,uuid,uuid,text,text,jsonb,bytea,uuid) TO "+reader+"; GRANT EXECUTE ON FUNCTION begin_context_query_capacity_observation(uuid,jsonb,jsonb,uuid,bigint),accept_context_query_capacity(uuid,jsonb,jsonb,jsonb),complete_context_query_capacity_observation(uuid,jsonb,timestamptz),allocate_context_query_capacity(uuid,uuid,uuid,text,text,uuid),suspend_context_query_capacity(uuid,timestamptz) TO "+writer); err != nil {
		t.Fatal("explicit fixture query purpose grants", err)
	}
	reads, err := postgres.NewContextQueryCapacityReads(ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	writes, err := postgres.NewContextQueryCapacityProducer(ctx, f.roles["capacity"], f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	guard := queryCapacitySyntheticGuard{}
	current := app.ProtectedContextQueryCapacity{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, Store: reads, Recovery: f.source, Deployments: app.QueryDeploymentGuards{Worker: guard, Hub: guard, KeyService: guard, Provider: guard}, Now: time.Now, NewID: custodyID}
	query := &queryLedgerFixture{base: f, enrolled: enrolled, current: current, producer: app.ProtectedContextQueryProducer{Current: current, Writer: writes}, key: app.WorkloadCapacityKey{RootID: current.RootID, ClusterID: scope.ClusterID, NamespaceUID: f.namespace.UID, WorkloadUID: f.workloads[0].UID}}
	// A real installed base root is insufficient without its separate accepted
	// query anchor. Check through the same narrow credential used by the ledger.
	probe := f.fixturePool("context_query_runtime", "synthetic-context-query")
	var allowed bool
	if err = probe.QueryRow(ctx, "SELECT lock_context_query_capacity($1,$2)", current.RootID, custodyID()).Scan(&allowed); err != nil || allowed {
		t.Fatal("missing query anchor did not deny", allowed, err)
	}
	probe.Close()
	processingPools := len(pools)
	f.initializeManagedProcessing(t, root)
	for _, p := range pools[processingPools:] {
		p.Close()
	}
	query.scenario, query.published = publishQueryLedgerContext(t, f, root, enrolled)
	query.refresh(t)
	query.audit = f.readAuditProfiles(t)
	qualifyContextQueries(t, query)
}

// Produce and independently publish an actual managed context. No download
// session, download policy or download authority supplies query admission.
func publishQueryLedgerContext(t *testing.T, f *capacitySQLFixture, root app.RootConfiguration, enrollment app.Enrollment) (captureAdmissionScenario, artifact.PublishedContext) {
	t.Helper()
	s, accepted := f.admitManagedContextRetention(t, root, enrollment, 60)
	e := accepted.Expectation
	bound, err := f.store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewContextProducer(bound, f.keys, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.PrepareContext(f.ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	at := time.Now().UTC()
	payload, err := json.Marshal(map[string]any{"format": artifact.ContextFormat, "namespaceUID": e.NamespaceUID, "podUID": e.PodUID, "resourceVersion": "synthetic-1", "observedAt": at, "phase": "Running", "ready": "True", "initialized": "True", "scheduled": "True", "runtimeInstances": 1, "running": 1, "waiting": 0, "terminated": 0, "restarts": 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	copies, err := prepared.StoreContext(f.ctx, payload, at, at)
	if err != nil {
		t.Fatal("managed encrypted query source", err)
	}
	verifier, err := objectstore.NewContextVerifier(bound, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	guards := postgres.EffectTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	var publicationPools []*pgxpool.Pool
	defer func() {
		for _, p := range publicationPools {
			p.Close()
		}
	}()
	publication := func(role, password string) *postgres.ContextPublications {
		p := f.fixturePool(role, password)
		publicationPools = append(publicationPools, p)
		ledger, err := postgres.NewContextPublications(f.ctx, p, s.a.RootID, guards)
		if err != nil {
			t.Fatal(err)
		}
		return ledger
	}
	check := publication("context_verify_runtime", "synthetic-context-verify")
	ack := publication("context_verification_audit_runtime", "synthetic-context-audit")
	publish := publication("context_publish_runtime", "synthetic-context-publish")
	f.refreshBase(t)
	publisher := evidence.ContextPublisher{Ledger: evidence.ContextPublicationFacets{ContextAcceptanceReader: check, ContextVerificationRecorder: check, ContextVerificationAuditor: ack, ContextCatalogPublisher: publish}, Authority: contextPublicationTestGate{check: func(ctx context.Context, v artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
		return f.currentManagedPublication(ctx, s, v)
	}}, Verifier: verifier, Audit: &objectstore.ContextVerificationObjects{Store: f.store, Seal: f.keys, Open: f.keys}, Now: time.Now}
	published, err := publisher.Publish(f.ctx, e.CaptureUID, copies)
	if err != nil {
		t.Fatal("managed independent query source publication", err)
	}
	return s, published
}
