package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authorizationapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Native55 persisted an audited worker without its launch claim. This tests
// that exact SQL/S3 interval with the installed grants, one authority observation
// and the real dispatcher. The existing fixture supplies synthetic protected
// sources/human identity and actual published evidence. Job creation is a stop
// boundary, not a simulated Kubernetes success or installed qualification.
func qualifyInstalledDownloadPreparation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, s captureAdmissionScenario, published artifact.PublishedContext, allocation artifact.DownloadAllocation, gate authorizationapp.ContextDownloadAuthority) {
	t.Helper()
	profile := syntheticWorkerProfile(s.recovery.installation)
	environment := gate.Environment.(downloadTestEnvironment)
	placement := environment.path
	placement.AcquisitionClusterID, placement.ConnectorClusterID, placement.WorkerConfiguration = profile.ClusterID, profile.ClusterID, profile.Configuration
	_, _, observer, _ := acceptedWorkerConfiguration(t, ctx, poolFor, store, keys, profile, environment.epoch)
	if s.nativeSources == nil {
		t.Fatal("joined fixture source owner missing")
	}
	s.nativeSources.SetWorker(t, observer.Observe)

	// Reuse the actual ordinary hub login and shared pool for these three typed
	// facets. This is a transaction fixture, not a whole-hub load measurement.
	sharedPools, _ := compiledOrdinaryHubPools(t, ctx, admin, poolFor)
	shared := sharedPools.ordinary
	guards := postgres.DownloadTransactionGuards{Retention: s.retention.guard, Recovery: s.recovery.guard}
	sessions, err := postgres.NewDownloads(ctx, shared, s.a.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := postgres.NewDownloadWorkers(ctx, shared, s.a.RootID, profile, guards)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := postgres.NewDownloadWorkers(ctx, shared, s.a.RootID, profile, guards)
	if err != nil {
		t.Fatal(err)
	}
	e := published.Expectation
	scope := artifact.DownloadScope{RootID: s.a.RootID, ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(published.Copies), Principal: s.a.Plan.Input.Executor}
	setupAuthority, err := gate.CheckDownload(ctx, "synthetic-reference", scope)
	if err != nil {
		t.Fatal("setup session authority", err)
	}
	now := time.Now().UTC()
	session, err := sessions.ReserveDownload(ctx, evidence.DownloadReservation{Session: artifact.DownloadSession{ID: custodyID(), AllocationID: allocation.ID, Scope: scope, RequestDigest: artifact.Digest{8}, State: artifact.DownloadPreparing, CreatedAt: now, Deadline: now.Add(5 * time.Minute), OutputLimit: 8192, ReadLimit: 8 << 20, RequestLimit: 4}, IdempotencyDigest: artifact.Digest{9}, Authority: setupAuthority})
	if err != nil {
		t.Fatal("setup session reservation", err)
	}

	// This is one fresh preparation of an already acknowledged session. Neither
	// the test nor the dispatcher obtains another authority after the first
	// complete real authorizer call. Every downstream context retains its bound.
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	until, _ := call.Deadline()
	trace := &installedPreparationTrace{t: t, started: time.Now(), until: until, DownloadWorkerLedger: workers, ack: ack, objects: &objectstore.DownloadWorkerAuditObjects{Store: store, Seal: keys, Open: keys}, gate: gate}
	jobs := &installedPreparationJobs{trace: trace}
	dispatch := evidence.DownloadDispatcher{Ledger: trace, Jobs: jobs, Audit: trace, Acknowledgements: trace, CurrentAuthority: trace, Profile: profile, Now: time.Now}
	_, err = dispatch.EnsureCurrent(call, installedPreparationIdentity{gate.Identities}, session.ID, custodyID(), scope)
	t.Logf("preparation result elapsed=%s original-request-left=%s authority-left=%s stages=%v error=%T/%v", time.Since(trace.started), time.Until(until), time.Until(trace.original.ValidUntil), trace.stages, err, err)
	if !errors.Is(err, errInstalledPreparationReachedJob) || jobs.calls != 1 {
		t.Fatal("original-authority preparation did not reach the first Job call", err, jobs.calls)
	}
	want := []string{"authority", "reserve", "read-audit", "write-audit", "ack-audit", "claim", "create-job-boundary"}
	if !slices.Equal(trace.stages, want) || trace.authorityCalls != 1 || trace.original != trace.claimed {
		t.Fatal("preparation reordered work or replaced its original authority", trace.stages, trace.authorityCalls)
	}
	var audited, claimed, noJob, noBinding bool
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM download_worker WHERE session_id=$1`, session.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected worker reservation count", count, err)
	}
	if err := admin.QueryRow(ctx, `SELECT audit_receipt_json IS NOT NULL, claimed_at IS NOT NULL, job_json IS NULL, binding_json IS NULL FROM download_worker WHERE session_id=$1`, session.ID).Scan(&audited, &claimed, &noJob, &noBinding); err != nil || !audited || !claimed || !noJob || !noBinding {
		t.Fatal("pre-Job durable state differs", audited, claimed, noJob, noBinding, err)
	}
}

type installedPreparationIdentity struct{ identities.Resolver }

func (s installedPreparationIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return s.Resolve(ctx, "synthetic-reference")
}

// Wrappers delegate once, retain exact errors and report original remaining
// intervals. No retry, clock replacement, authority refresh or SQL mutation is
// added by this trace. The dispatcher calls all these ports synchronously.
type installedPreparationTrace struct {
	evidence.DownloadWorkerLedger
	t                 *testing.T
	started, until    time.Time
	stages            []string
	authorityCalls    int
	original, claimed artifact.DownloadAuthority
	ack               *postgres.DownloadWorkers
	objects           *objectstore.DownloadWorkerAuditObjects
	gate              authorizationapp.ContextDownloadAuthority
}

func (s *installedPreparationTrace) stage(ctx context.Context, name string, err error) {
	s.t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(s.until) || !s.original.ValidUntil.IsZero() && deadline.After(s.original.ValidUntil) {
		s.t.Fatalf("%s lost original deadline", name)
	}
	s.stages = append(s.stages, name)
	s.t.Logf("preparation stage=%s elapsed=%s call-left=%s authority-left=%s error=%T/%v", name, time.Since(s.started), time.Until(deadline), time.Until(s.original.ValidUntil), err, err)
}

func (s *installedPreparationTrace) CheckDownloadCurrent(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	s.authorityCalls++
	a, err := s.gate.CheckDownloadCurrent(ctx, current, scope)
	// The authorizer may discover an earlier cutoff than this input context;
	// workerCurrentCheck must impose it on every subsequent effect.
	s.stage(ctx, "authority", err)
	s.t.Logf("authority checked=%s valid-until=%s retention-until=%s environment-until=%s", a.CheckedAt.Format(time.RFC3339Nano), a.ValidUntil.Format(time.RFC3339Nano), a.Retention.ValidUntil.Format(time.RFC3339Nano), a.Environment.ValidUntil.Format(time.RFC3339Nano))
	return a, err
}

func (s *installedPreparationTrace) ReserveDownloadWorker(ctx context.Context, session, id string, a artifact.DownloadAuthority, p value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	s.original = a
	i, err := s.DownloadWorkerLedger.ReserveDownloadWorker(ctx, session, id, a, p)
	s.stage(ctx, "reserve", err)
	return i, err
}

func (s *installedPreparationTrace) ReadDownloadWorkerIntentReceipt(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, bool, error) {
	r, ok, err := s.DownloadWorkerLedger.ReadDownloadWorkerIntentReceipt(ctx, i)
	s.stage(ctx, "read-audit", err)
	if ok {
		s.t.Fatal("fresh worker inherited an audit receipt")
	}
	return r, ok, err
}

func (s *installedPreparationTrace) WriteDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, error) {
	r, err := s.objects.WriteDownloadWorkerIntent(ctx, i)
	s.stage(ctx, "write-audit", err)
	return r, err
}

func (s *installedPreparationTrace) AcknowledgeDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent, r audit.Receipt) error {
	err := s.ack.AcknowledgeDownloadWorkerIntent(ctx, i, r)
	s.stage(ctx, "ack-audit", err)
	return err
}

func (s *installedPreparationTrace) ClaimDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, a artifact.DownloadAuthority) (value.DownloadWorkerLaunch, error) {
	s.claimed = a
	launch, err := s.DownloadWorkerLedger.ClaimDownloadWorker(ctx, i, a)
	s.stage(ctx, "claim", err)
	return launch, err
}

var errInstalledPreparationReachedJob = errors.New("test stopped before Kubernetes Job creation")

type installedPreparationJobs struct {
	evidence.DownloadWorkerJobs
	trace *installedPreparationTrace
	calls int
}

func (s *installedPreparationJobs) CreateDownloadWorker(ctx context.Context, l value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	s.calls++
	s.trace.stage(ctx, "create-job-boundary", nil)
	if !l.MayCreate || !l.Valid(time.Now()) || !l.Until.Equal(s.trace.original.ValidUntil) {
		return value.DownloadWorkerJob{}, errors.New("invalid original launch at first Job boundary")
	}
	return value.DownloadWorkerJob{}, errInstalledPreparationReachedJob
}
