package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This owns a pristine installation, its real protected capacity root and
// additive query reservation. Run separately from other pristine-root cases.
// Protected placement/native source observations, human identity and C14
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
	base           *capacitySQLFixture
	enrolled       app.Enrollment
	current        *postgres.SharedContextQueryPlans
	policies       *authapp.ContextProjectionPolicies
	profile        value.ContextQueryResourceProfile
	workerProfile  authorization.DownloadWorkerProfile
	workerObserver *evidence.WorkerConfigurationObserver
	workerConfig   *postgres.WorkerConfigurations
	scenario       captureAdmissionScenario
	published      artifact.PublishedContext
	audit          audit.AcceptedCapacityAuditProfiles
}

func (f *queryLedgerFixture) currentProfile() value.ContextQueryResourceProfile {
	return f.profile
}

// New source observations precede new requests. They never modify an admitted
// query, batch or its original deadlines. The existing capacity source
// producer refreshes the same accepted workload; query charges never refill.
func (f *queryLedgerFixture) refresh(t *testing.T) {
	t.Helper()
	o := f.base.workloadObservation(t, 0)
	if err := f.base.enrollments.RefreshCapacityEnrollment(f.base.ctx, o, f.enrolled); err != nil {
		t.Fatal("current managed workload", err)
	}
	if f.workerObserver != nil {
		if err := f.workerObserver.Observe(f.base.ctx); err != nil {
			t.Fatal("current accepted shared worker", err)
		}
	}
}

func queryLedgerQualification(t *testing.T, f *capacitySQLFixture) {
	t.Helper()
	syntheticQueryCapacityQualification(t, f)
	q := f.qualification.ContextQuery
	q.Profile.Lifetime = 60 * time.Second
	q.PrincipalQueries = 2
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
	withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyContextQueries)
}

func withProtectedContextQueryLedger(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects, qualify func(*testing.T, *queryLedgerFixture)) {
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
	// The existing capacity role published the anchor/allocation in its own
	// transactions. There is no query producer or extra source-observation claim.
	query := &queryLedgerFixture{base: f, enrolled: enrolled}
	processingPools := len(pools)
	f.initializeManagedProcessing(t, root)
	for _, p := range pools[processingPools:] {
		p.Close()
	}
	query.scenario, query.published = publishQueryLedgerContext(t, f, root, enrolled)
	profile := syntheticWorkerProfile(f.input.InstallationID)
	profile.ClusterID = scope.ClusterID
	profile.Configuration = f.qualification.ContextQuery.Profile.Source
	profile.StoreCredentialSecret, profile.StoreCredentialSecretUID = "query-fixture-store", custodyID()
	query.workerProfile = profile
	recovery, err := f.source.RecoveryState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	query.workerConfig, _, query.workerObserver, _ = acceptedWorkerConfiguration(t, ctx, f.fixturePool, f.store, f.keys, profile, recovery.IssuerEpoch)
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: f.qualification.ContextQuery.Profile.ID, TargetClusterID: scope.ClusterID, StoreID: f.qualification.Backends[0].EvidenceStoreID, StorageRegion: "local", AcquisitionClusterID: profile.ClusterID, AcquisitionRegion: "local", ConnectorClusterID: profile.ClusterID, ConnectorRegion: "local", HubClusterID: scope.ClusterID, HubRegion: "local", WorkerConfiguration: profile.Configuration, HubConfiguration: profile.Configuration}
	query.profile, err = f.qualification.ContextQuery.Profile.WithSharedPath(path)
	if err != nil {
		t.Fatal(err)
	}
	query.current, err = postgres.NewSharedContextQueryPlans(ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID, profile)
	if err != nil {
		t.Fatal(err)
	}
	raw := querySQLPolicy{root: f.input.PermissionRootID, installation: f.input.InstallationID, epoch: recovery.IssuerEpoch, path: path}
	query.policies, err = authapp.NewContextProjectionPolicies(raw, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	query.refresh(t)
	query.audit = f.readAuditProfiles(t)
	qualify(t, query)
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

// Protected placement is synthetic in this SQL fixture. The production typed
// adapter is exercised; human read approval and current SQL fences stay real.
type querySQLPolicy struct {
	root, installation, epoch string
	path                      value.ContextProjectionPath
}

func (p querySQLPolicy) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	if ctx.Err() != nil {
		return privacy.DownloadPolicy{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	x := p.path
	path := artifact.DownloadPath{ID: x.ID, TargetClusterID: x.TargetClusterID, StoreID: x.StoreID, StorageRegion: x.StorageRegion, AcquisitionClusterID: x.AcquisitionClusterID, AcquisitionRegion: x.AcquisitionRegion, ConnectorClusterID: x.ConnectorClusterID, ConnectorRegion: x.ConnectorRegion, HubClusterID: x.HubClusterID, HubRegion: x.HubRegion, WorkerConfiguration: x.WorkerConfiguration, HubConfiguration: x.HubConfiguration}
	clients := []privacy.DownloadClient{}
	for _, name := range []string{"console", "fixture-other-client"} {
		clients = append(clients, privacy.DownloadClient{Issuer: "https://id.example.test", ID: name, Kind: identity.Human, DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}})
	}
	return privacy.DownloadPolicy{RootID: p.root, InstallationID: p.installation, RecoveryEpoch: p.epoch, Revision: x.WorkerConfiguration, ProtectionDigest: artifact.Digest{41}, PermittedRegions: []string{"local"}, Paths: []artifact.DownloadPath{path}, Clients: clients, Operators: []privacy.ProcessingOperator{{Issuer: "https://id.example.test", ClientID: "console", Kind: "User", ID: "fixture"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}
