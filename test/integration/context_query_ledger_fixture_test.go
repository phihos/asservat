package integration

import (
	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/adapters/syscalls"
	executionapp "asservat.local/asservat/internal/application/execution"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/execution"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	pprof "github.com/google/pprof/profile"
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

func TestProfileSummaryQueryLedgerWithRealPostgres(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		t.Run("profile-summary-source-and-ledger", func(t *testing.T) {
			withProtectedContextQueryLedger(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, qualifyContextQueries, true)
		})
	})
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
	base                 *capacitySQLFixture
	enrolled             app.Enrollment
	current              *postgres.SharedContextQueryPlans
	policies             *authapp.ContextProjectionPolicies
	profile              value.ContextQueryResourceProfile
	workerProfile        authorization.DownloadWorkerProfile
	workerObserver       *evidence.WorkerConfigurationObserver
	workerConfig         *postgres.WorkerConfigurations
	scenario             captureAdmissionScenario
	published            artifact.PublishedContext
	audit                audit.AcceptedCapacityAuditProfiles
	root                 app.RootConfiguration
	initialResultGrantID string
	// workloadGone stops refreshing the workload's capacity observation, as
	// after the source workload's deletion (maintainer decision 2026-10-23).
	workloadGone bool
}

func (f *queryLedgerFixture) currentProfile() value.ContextQueryResourceProfile {
	return f.profile
}

// New source observations precede new requests. They never modify an admitted
// query, batch or its original deadlines. The existing capacity source
// producer refreshes the same accepted workload; query charges never refill.
func (f *queryLedgerFixture) refresh(t *testing.T) {
	t.Helper()
	if !f.workloadGone {
		o := f.base.workloadObservation(t, 0)
		if err := f.base.enrollments.RefreshCapacityEnrollment(f.base.ctx, o, f.enrolled); err != nil {
			t.Fatal("current managed workload", err)
		}
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

func withProtectedContextQueryLedger(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects, qualify func(*testing.T, *queryLedgerFixture), profileSource ...bool) {
	isProfile := len(profileSource) > 0 && profileSource[0]
	isComparison := len(profileSource) > 1 && profileSource[1]
	legacyTiming := len(profileSource) > 2 && profileSource[2]
	isPacket := len(profileSource) > 3 && profileSource[3]
	rawPacket := len(profileSource) > 4 && profileSource[4]
	rawSyscall := len(profileSource) > 5 && profileSource[5]
	isLogs := len(profileSource) > 6 && profileSource[6]
	logsGroup := len(profileSource) > 7 && profileSource[7]
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects, func(f *capacitySQLFixture) {
		queryLedgerQualification(t, f)
		if isLogs {
			logsLedgerFunding(t, f, logsGroup)
		}
		if isPacket || rawSyscall {
			packetLedgerFunding(t, f)
		}
		if isProfile || isPacket || rawSyscall || isLogs {
			q := f.qualification.ContextQuery
			q.Profile.Worker.MemoryBytes, q.Profile.Worker.WorkerTransientBytes = value.ProfileSummaryWorkerBytes, value.ProfileSummaryWorkerBytes
			q.RootQueries, q.PrincipalQueries, q.WorkloadQueries = 20, 20, 20
			if isComparison {
				comparisonLedgerQualification(q)
			}
			var err error
			q.Envelope, err = q.Required()
			if err != nil || !f.qualification.Valid() {
				t.Fatal("original summary backing", err)
			}
		}
	})
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
	query := &queryLedgerFixture{base: f, enrolled: enrolled, root: root}
	processingPools := len(pools)
	f.initializeManagedProcessing(t, root)
	for _, p := range pools[processingPools:] {
		p.Close()
	}
	query.scenario, query.published = publishQueryLedgerContext(t, f, root, enrolled, isProfile, legacyTiming, isPacket, rawPacket, rawSyscall, isLogs)
	profile := syntheticWorkerProfile(f.input.InstallationID)
	if isProfile || isPacket || rawSyscall || isLogs {
		profile.MemoryBytes = value.ProfileSummaryWorkerBytes
		if isComparison {
			profile.MemoryBytes = value.ProfileComparisonWorkerBytes
		}
	}
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
	raw := querySQLPolicy{root: f.input.PermissionRootID, installation: f.input.InstallationID, epoch: recovery.IssuerEpoch, path: path, profile: isProfile, packet: isPacket, syscall: rawSyscall, logs: isLogs}
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
func publishQueryLedgerContext(t *testing.T, f *capacitySQLFixture, root app.RootConfiguration, enrollment app.Enrollment, profileSource bool, legacyTiming ...bool) (captureAdmissionScenario, artifact.PublishedContext) {
	t.Helper()
	var s captureAdmissionScenario
	var accepted capture.Accepted
	var profileSQL *postgres.APIContextExecutions
	var started execution.APIExecution
	var refresh func() executionapp.APIExecutionCheck
	packetSource := len(legacyTiming) > 1 && legacyTiming[1]
	rawPacket := len(legacyTiming) > 2 && legacyTiming[2]
	rawSyscall := len(legacyTiming) > 3 && legacyTiming[3]
	isLogs := len(legacyTiming) > 4 && legacyTiming[4]
	if isLogs {
		s, accepted, profileSQL = admitQueryLedgerProfile(t, f, root, enrollment, false, false, true)
		started, refresh = startQueryLedgerProfile(t, f, s, accepted, profileSQL)
	} else if rawSyscall {
		s, accepted, profileSQL = admitQueryLedgerProfile(t, f, root, enrollment, false, true)
		started, refresh = startQueryLedgerProfile(t, f, s, accepted, profileSQL)
	} else if packetSource {
		if rawPacket {
			s, accepted, profileSQL = admitQueryLedgerProfile(t, f, root, enrollment, true)
		} else {
			s, accepted, profileSQL = admitQueryLedgerPacket(t, f, root, enrollment)
		}
		started, refresh = startQueryLedgerProfile(t, f, s, accepted, profileSQL)
	} else if profileSource {
		s, accepted, profileSQL = admitQueryLedgerProfile(t, f, root, enrollment)
		started, refresh = startQueryLedgerProfile(t, f, s, accepted, profileSQL)
	} else {
		s, accepted = f.admitManagedContextRetention(t, root, enrollment, 60)
	}
	return publishPreparedQueryLedgerContext(t, f, s, accepted, profileSQL, started, refresh, len(legacyTiming) > 0 && legacyTiming[0])
}

// Reuse the exact existing custody/publication flow for already admitted group
// children; only their independent admission is different.
func publishPreparedQueryLedgerContext(t *testing.T, f *capacitySQLFixture, s captureAdmissionScenario, accepted capture.Accepted, profileSQL *postgres.APIContextExecutions, started execution.APIExecution, refresh func() executionapp.APIExecutionCheck, legacy bool) (captureAdmissionScenario, artifact.PublishedContext) {
	t.Helper()
	profileSource := accepted.Expectation.Profile != nil
	packetSource := accepted.Expectation.Recording != nil && accepted.Expectation.Recording.Kind == "packetCapture"
	rawPacket := accepted.Expectation.NativeType == artifact.RawPCAPNGArtifact
	rawSyscall := accepted.Expectation.NativeType == artifact.SyscallArgumentsArtifact
	isLogs := accepted.Expectation.Logs != nil
	e := accepted.Expectation
	if isLogs {
		assertLogsOriginalCollectCutoff(t, f.ctx, profileSQL, e)
	}
	bound, err := f.store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	var copies artifact.Copies
	var acquisition artifact.AcquisitionWindow
	if profileSource || packetSource || rawSyscall || isLogs {
		var prepared *objectstore.PreparedArtifact
		if isLogs && e.Registration.NativeLimit > artifact.FrameBytes {
			// Match the actual connector writer: the pending SQL obligation is
			// already charged and bound, while the process-owned journal cannot
			// release it. Other one-frame fixture sources retain their old path.
			plan := artifact.StreamingPlan{Registration: e.Registration, WriterEpoch: started.Process.ProcessEpoch}
			encoded, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			wantDigest := sha256.Sum256(encoded)
			var epoch string
			var storedDigest []byte
			var temporaryBytes, temporaryObjects int64
			var charged bool
			if err = f.admin.QueryRow(f.ctx, `SELECT writer_epoch::text,plan_digest,temporary_bytes,temporary_objects,released_at IS NULL FROM custody_stream WHERE attempt_id=$1`, e.Registration.Location.AttemptID).Scan(&epoch, &storedDigest, &temporaryBytes, &temporaryObjects, &charged); err != nil || epoch != plan.WriterEpoch || !bytes.Equal(storedDigest, wantDigest[:]) || temporaryBytes != plan.TemporaryBytes() || temporaryObjects != int64(1+plan.PartLimit()) || !charged {
				t.Fatalf("original logs multipart obligation epochMatches=%t digestMatches=%t bytes=%d/%d objects=%d/%d charged=%t err=%v", epoch == plan.WriterEpoch, bytes.Equal(storedDigest, wantDigest[:]), temporaryBytes, plan.TemporaryBytes(), temporaryObjects, 1+plan.PartLimit(), charged, err)
			}
			prepared, err = objectstore.PrepareOneShotLogsArtifact(f.ctx, bound, f.keys, e, plan.WriterEpoch, time.Now)
		} else {
			producer, createErr := objectstore.NewArtifactProducer(bound, f.keys, unusedStreamingJournal{}, time.Now)
			if createErr != nil {
				t.Fatal(createErr)
			}
			prepared, err = producer.Prepare(f.ctx, e, "")
		}
		if err != nil {
			t.Fatal("managed original writer preparation", err)
		}
		var body bytes.Buffer
		at := time.Now().UTC()
		if isLogs {
			body.Write(logsQuerySyntheticNative(t, e, started.StartedAt, time.Now().UTC()))
			at = time.Now().UTC()
		} else if rawSyscall {
			time.Sleep(2 * time.Millisecond)
			at = time.Now().UTC().Truncate(time.Microsecond)
			original := installedArgumentsSQLSource(t, f.ctx, f.admin, s.a.RootID)(e.CaptureUID)
			body.Write(syscallQuerySyntheticNative(t, e, original, started.StartedAt, at))
		} else if packetSource {
			// Explicit synthetic node payload; no privileged collector. Keep
			// every packet/footer within the real started/completed interval.
			time.Sleep(2 * time.Millisecond)
			at = time.Now().UTC()
			if rawPacket {
				body.Write(syntheticRawPacketSummaryRecording(t, started.StartedAt, at))
			} else {
				body.Write(syntheticFilteredRecording(t, started.StartedAt, recordingProgram, 0, syntheticRecordingTimes{Step: time.Microsecond, End: at}))
			}
		} else {
			function := &pprof.Function{ID: 1, Name: "synthetic.work"}
			location := &pprof.Location{ID: 1, Line: []pprof.Line{{Function: function}}}
			native := &pprof.Profile{PeriodType: &pprof.ValueType{Type: "cpu", Unit: "nanoseconds"}, SampleType: []*pprof.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, Function: []*pprof.Function{function}, Location: []*pprof.Location{location}, Sample: []*pprof.Sample{{Location: []*pprof.Location{location}, Value: []int64{7}}}}
			if err = native.Write(&body); err != nil {
				t.Fatal(err)
			}
			if err = diagnostics.CheckPprof(bytes.NewReader(body.Bytes())); err != nil {
				t.Fatal("synthetic profile shape", err)
			}
			at = time.Now().UTC()
		}

		acquisition = artifact.AcquisitionWindow{StartedAt: started.StartedAt.UTC().Truncate(time.Microsecond), CompletedAt: at.Truncate(time.Microsecond)}
		copies, err = prepared.Store(f.ctx, bytes.NewReader(body.Bytes()), started.StartedAt, at)
		clear(body.Bytes())
		if err != nil {
			t.Fatal("managed encrypted profile source", err)
		}
		stored := time.Now().UTC().Truncate(time.Microsecond)
		started.Copies, started.Phase, started.AcquiredAt, started.CompletedAt = copies, "stored", at.Truncate(time.Microsecond), stored
		c := refresh()
		completion := artifact.ContextWriterCompletion{RegistrationDigest: privacyapp.RegistrationDigest(e.Registration), ExpectationDigest: evidence.ContextExpectationDigest(e), Copies: copies, StoredAt: stored, ClosedAt: stored}
		if _, err = profileSQL.RecordAPIStoredCompletion(f.ctx, started, completion, c.Process, c.Recovery); err != nil {
			t.Fatal("managed profile stored completion", err)
		}

	} else {
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
		copies, err = prepared.StoreContext(f.ctx, payload, at, at)
		if err != nil {
			t.Fatal("managed encrypted query source", err)
		}

	}
	verifier, err := objectstore.NewContextVerifier(bound, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	if rawSyscall {
		original := installedArgumentsSQLSource(t, f.ctx, f.admin, s.a.RootID)(e.CaptureUID)
		verifier.WithStreamCheck(artifact.SyscallArgumentsArtifact, func(expected artifact.ContextExpectation) objectstore.StreamCheck {
			check, err := syscalls.NewArgumentCheck(expected, original.Source)
			if err != nil {
				t.Fatal(err)
			}
			return check
		})
	} else if rawPacket {
		verifier.WithStreamCheck(artifact.RawPCAPNGArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck {
			return packets.NewRawCheck(packets.RawLimits{Snaplen: 96, TCP: manualRawTCPCap})
		})
	} else if packetSource {
		verifier.WithStreamCheck(artifact.PCAPNGArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return packets.NewHeadersCheck() })
	} else if profileSource {
		verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewPprofCheck() })
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
	if profileSource || packetSource || rawSyscall || isLogs {
		gatePool := f.fixturePool("api_publication_gate_runtime", "synthetic-api-publication-gate")
		defer gatePool.Close()
		gate, err := postgres.NewAPIContextPublicationGate(f.ctx, gatePool, s.a.RootID, guards, privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, s.recovery.reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher.Authority = gate
	}
	var probe profileAcquisitionPublicationProbe
	if profileSource {
		probe = qualifyProfileAcquisitionBeforePublication(t, f, s, publisher, check, e, copies, acquisition, legacy)
	}
	published, err := publisher.Publish(f.ctx, e.CaptureUID, copies)
	if err != nil {
		t.Fatal("managed independent query source publication", err)
	}
	if profileSource {
		qualifyProfileAcquisitionAfterPublication(t, f, s, publisher, check, e, copies, probe)
	}
	return s, published
}

// Protected placement is synthetic in this SQL fixture. The production typed
// adapter is exercised; human read approval and current SQL fences stay real.
type querySQLPolicy struct {
	root, installation, epoch string
	path                      value.ContextProjectionPath
	profile                   bool
	packet                    bool
	syscall                   bool
	logs                      bool
}

func (p querySQLPolicy) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	if ctx.Err() != nil {
		return privacy.DownloadPolicy{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	x := p.path
	path := artifact.DownloadPath{ID: x.ID, TargetClusterID: x.TargetClusterID, StoreID: x.StoreID, StorageRegion: x.StorageRegion, AcquisitionClusterID: x.AcquisitionClusterID, AcquisitionRegion: x.AcquisitionRegion, ConnectorClusterID: x.ConnectorClusterID, ConnectorRegion: x.ConnectorRegion, HubClusterID: x.HubClusterID, HubRegion: x.HubRegion, WorkerConfiguration: x.WorkerConfiguration, HubConfiguration: x.HubConfiguration}
	classes, evidenceTypes := []string{"metadata"}, []string{"context"}
	if p.logs {
		classes, evidenceTypes = []string{"raw"}, []string{"logs"}
	} else if p.syscall {
		classes, evidenceTypes = []string{"extract"}, []string{"syscallTrace"}
	} else if p.packet {
		classes, evidenceTypes = []string{"extract"}, []string{"packetCapture"}
	} else if p.profile {
		classes, evidenceTypes = []string{"extract"}, []string{"profile"}
	}
	clients := []privacy.DownloadClient{}
	for _, name := range []string{"console", "fixture-other-client"} {
		clients = append(clients, privacy.DownloadClient{Issuer: "https://id.example.test", ID: name, Kind: identity.Human, DataClasses: classes, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: evidenceTypes, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}})
	}
	return privacy.DownloadPolicy{RootID: p.root, InstallationID: p.installation, RecoveryEpoch: p.epoch, Revision: x.WorkerConfiguration, ProtectionDigest: artifact.Digest{41}, PermittedRegions: []string{"local"}, Paths: []artifact.DownloadPath{path}, Clients: clients, Operators: []privacy.ProcessingOperator{{Issuer: "https://id.example.test", ClientID: "console", Kind: "User", ID: "fixture"}}, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, nil
}
