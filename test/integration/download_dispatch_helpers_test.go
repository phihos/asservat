package integration

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
	"time"
)

type countedWorkerAudit struct {
	writer auditapp.DownloadWorkerWriter
	writes int
}

type countedWorkerConfigurationAudit struct {
	writer auditapp.WorkerConfigurationWriter
	writes int
}

func (a *countedWorkerConfigurationAudit) WriteWorkerConfiguration(ctx context.Context, c value.DownloadWorkerConfiguration) (audit.Receipt, error) {
	a.writes++
	return a.writer.WriteWorkerConfiguration(ctx, c)
}

type workerObservationFunc func(context.Context) (value.DownloadWorkerObservation, error)

func (f workerObservationFunc) ReadWorkerConfiguration(c context.Context) (value.DownloadWorkerObservation, error) {
	return f(c)
}

// Synthetic protected source only; persistence, audit encryption and S3 are real.
func acceptedWorkerConfiguration(t *testing.T, ctx context.Context, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, profile value.DownloadWorkerProfile, epoch string) (*postgres.WorkerConfigurations, *postgres.WorkerConfigurations, *evidence.WorkerConfigurationObserver, *value.DownloadWorkerConfiguration) {
	t.Helper()
	makeLedger := func(role, password string) *postgres.WorkerConfigurations {
		pool := poolFor(role, password)
		t.Cleanup(pool.Close)
		l, e := postgres.NewWorkerConfigurations(ctx, pool, profile.InstallationID, profile.ClusterID, profile.NamespaceUID, profile.Configuration.UID)
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	l := makeLedger("worker_configuration_runtime", "synthetic-worker-configuration")
	a := makeLedger("worker_configuration_audit_runtime", "synthetic-worker-configuration-audit")
	r := makeLedger("worker_configuration_read_runtime", "synthetic-worker-configuration-read")
	c := &value.DownloadWorkerConfiguration{Profile: profile, RecoveryEpoch: epoch, ProtectionDigest: artifact.Digest{17}}
	observer := &evidence.WorkerConfigurationObserver{Reader: workerObservationFunc(func(context.Context) (value.DownloadWorkerObservation, error) {
		now := time.Now().UTC()
		return value.DownloadWorkerObservation{Configuration: *c, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
	}), Ledger: l, Audit: &objectstore.WorkerConfigurationAuditObjects{Store: store, Seal: keys, Open: keys}, Acknowledgements: a, Now: time.Now}
	if e := observer.Observe(ctx); e != nil {
		t.Fatal("worker configuration acceptance", e)
	}
	return l, r, observer, c
}

func (a *countedWorkerAudit) WriteDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, error) {
	a.writes++
	return a.writer.WriteDownloadWorkerIntent(ctx, i)
}

func syntheticWorkerProfile(installation string) value.DownloadWorkerProfile {
	return value.DownloadWorkerProfile{Configuration: identity.Revision{UID: custodyID(), Generation: 1, Digest: [32]byte{11}}, InstallationID: installation, ClusterID: custodyID(), Namespace: "workers", NamespaceUID: "namespace-uid", ServiceAccount: "acquisition", ServiceAccountUID: "account-uid", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config-uid", PriorityClass: "download-workers", PriorityClassUID: "priority-uid", ControlDigest: artifact.Digest{3}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute}
}

// SQL/audit coordinator fixture only. Real Kubernetes creation and termination
// are independently exercised by TestDownloadJobsWithRealKubernetes.
type syntheticDownloadJobs struct {
	worker                                value.DownloadWorker
	creates, finds, terminations, deletes int
	loseCreate, loseDelete, stopped       bool
}

func (s *syntheticDownloadJobs) CreateDownloadWorker(_ context.Context, l value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	s.creates++
	i, p := l.Intent, l.Intent.Profile
	j := value.DownloadWorkerJob{IntentID: i.ID, UID: custodyID(), Spec: artifact.Digest{5}}
	s.worker = value.DownloadWorker{Intent: i, Job: j, Binding: value.KeyWorkerBinding{InstallationID: p.InstallationID, DownloadID: i.SessionID, ClusterID: p.ClusterID, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: i.JobName(), JobUID: j.UID, JobSpec: j.Spec, Pod: "worker-pod", PodUID: custodyID(), PodSpec: artifact.Digest{6}}}
	if s.loseCreate {
		s.loseCreate = false
		return value.DownloadWorkerJob{}, artifact.ErrDownloadUnavailable
	}
	return j, nil
}
func (s *syntheticDownloadJobs) FindDownloadWorkerJob(context.Context, value.DownloadWorkerIntent) (value.DownloadWorkerJob, error) {
	s.finds++
	if !s.worker.Valid() {
		return value.DownloadWorkerJob{}, artifact.ErrDownloadUnavailable
	}
	return s.worker.Job, nil
}
func (s *syntheticDownloadJobs) ObserveDownloadWorker(context.Context, value.DownloadWorkerIntent, value.DownloadWorkerJob) (value.DownloadWorker, error) {
	return s.worker, nil
}
func (s *syntheticDownloadJobs) ObserveDownloadWorkerTermination(context.Context, value.DownloadWorker) (value.DownloadWorkerTermination, error) {
	s.terminations++
	if !s.stopped {
		return value.DownloadWorkerTermination{}, artifact.ErrDownloadUnavailable
	}
	now := time.Now().UTC()
	return value.DownloadWorkerTermination{Worker: s.worker, TerminationDigest: artifact.Digest{8}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}
func (s *syntheticDownloadJobs) RetireDownloadWorker(_ context.Context, p value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error) {
	s.deletes++
	if s.loseDelete {
		s.loseDelete = false
		return value.DownloadWorkerRetirement{}, artifact.ErrDownloadUnavailable
	}
	now := time.Now().UTC()
	return value.DownloadWorkerRetirement{Termination: p, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

// noQueryWorkerCleanup isolates native download retirement in the shared
// admission cleanup; it offers no query workers.
type noQueryWorkerCleanup struct {
	evidence.ProjectionCleanupLedger
	evidence.ProjectionCleanupJobs
}

func (noQueryWorkerCleanup) ExpiredProjectionWorkers(context.Context) ([]evidence.ProjectionCleanupCandidate, error) {
	return nil, nil
}
