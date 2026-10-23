package bootstrap

import (
	"context"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	analysisapp "asservat.local/asservat/internal/application/analysis"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publicProjectionReader adapts only application port shapes. The public request
// owner, exact retained query and native handle pass through without authority
// reconstruction or evidence in the hub.
type publicProjectionReader struct {
	ledger  *postgres.ContextQueries
	runtime *evidence.ProjectionRuntime
}

func (s publicProjectionReader) ObserveProjectionWorker(ctx context.Context, q query.ContextQuery, owner analysisapp.ContextProjectionRequestOwner) (analysisapp.ContextProjectionWorkerObservation, error) {
	o, err := s.runtime.ObserveProjectionWorker(ctx, q, owner)
	return analysisapp.ContextProjectionWorkerObservation{Worker: o.Worker, Ready: o.Ready, ObservedAt: o.ObservedAt, ValidUntil: o.ValidUntil}, err
}
func (s publicProjectionReader) ReadProjection(ctx context.Context, start query.ContextReadStart, owner analysisapp.ContextProjectionRequestOwner) (analysisapp.ContextProjectionRead, error) {
	if owner == nil {
		return nil, query.ErrUnavailable
	}
	q, err := s.ledger.LookupQuery(ctx, owner.Request().Call.Principal, start.Batch.QueryID)
	if err != nil {
		return nil, err
	}
	return s.runtime.ReadProjection(ctx, q, start, owner)
}

type publicProjectionAdmission struct {
	admission *evidence.ProjectionWorkerAdmission
}

func (s publicProjectionAdmission) AdmitProjectionWorker(ctx context.Context, q query.ContextQuery, owner analysisapp.ContextProjectionRequestOwner) error {
	return s.admission.AdmitProjectionWorker(ctx, q, owner)
}

// The existing installed worker source, physical Job capacity, provider audit
// store and native listener serve a second closed purpose. All selection and SQL
// effects use ReadApproved; no native download session or authority is invented.
func newPublicProjection(ctx context.Context, d *OwnerDeployment, policy authapp.DownloadPolicyReader, processing *postgres.ProcessingReads, profile authorization.DownloadWorkerProfile, jobs *kube.DownloadWorkerJobs, dispatch *evidence.DownloadDispatcher, pool *pgxpool.Pool, scope authorization.KeyScope, audit publicAuditStore) (*analysisapp.ContextProjectionService, error) {
	if d == nil || d.publicContext == nil || d.Runtime == nil || d.Runtime.native == nil || d.Runtime.started.Load() || policy == nil || processing == nil || jobs == nil || dispatch == nil || pool == nil {
		return nil, mounts.ErrUnavailable
	}
	root, installation := d.inputs.config.PermissionRootID, d.inputs.config.InstallationID
	planPool, err := d.public.open(ctx, "capacity-profile-read")
	if err != nil {
		return nil, err
	}
	plans, err := postgres.NewSharedContextQueryPlans(ctx, planPool, root, installation, profile)
	if err != nil {
		return nil, err
	}
	ledger, err := postgres.NewContextQueries(ctx, pool, root, d.shared.guards, plans, nil)
	if err != nil {
		return nil, err
	}
	workers, err := postgres.AttachProjectionWorkers(ledger, profile)
	if err != nil {
		return nil, err
	}
	operations, err := postgres.NewProjectionNativeOperations(ledger)
	if err != nil {
		return nil, err
	}
	policies, err := authapp.NewContextProjectionPolicies(policy, time.Now)
	if err != nil {
		return nil, err
	}
	metadata, err := d.public.open(ctx, "hub-metadata-read")
	if err != nil {
		return nil, err
	}
	routes, err := postgres.NewContextCaseReads(ctx, metadata, root, d.shared.guards.Recovery)
	if err != nil {
		return nil, err
	}
	pc := d.publicContext
	// Evidence reads observe recovery for up to the evidence-read window.
	recovery := pc.recovery.ForEvidenceReads()
	authority := authapp.ContextProjectionAuthority{RootID: root, Permissions: pc.permissions, Catalog: pc.catalog, Retention: pc.retention,
		Environment: authapp.CurrentProjectionEnvironment{RootID: root, InstallationID: installation, Policies: policies, Recovery: recovery, Processing: processing, Now: time.Now}, Now: time.Now}
	origins := d.shared.origins
	origins.Projection = operations
	client := d.shared.workers[ownerNativeAPIKey{profile.ClusterID, profile.NamespaceUID}]
	if client == nil {
		return nil, mounts.ErrUnavailable
	}
	origins.ProjectionProofs = func(token evidence.DownloadPeerToken) (evidence.AcquisitionPeerProofReader, error) {
		return kube.NewDispatchedAcquisitionPeerAttester(client, operations, token)
	}
	cleanup := &evidence.ProjectionWorkerCleanup{Ledger: workers, Jobs: jobs, Now: time.Now, Report: eventLog(os.Stderr, "query worker cleanup")}
	runtime := &evidence.ProjectionRuntime{Cleanup: cleanup, Workers: workers, Identities: workers, Jobs: jobs, Sources: operations, Operations: operations, Origins: origins, Registrar: d.Runtime,
		KeyScope: scope, HubPodUID: d.Runtime.binding.PodUID, HubProcessEpoch: d.Runtime.binding.ProcessEpoch, Now: time.Now}
	reader := publicProjectionReader{ledger, runtime}
	service := &analysisapp.ContextProjectionService{Results: analysisapp.ContextProjectionResults{RootID: root, InstallationID: installation, HubProcessEpoch: d.Runtime.binding.ProcessEpoch,
		Authority: authority, Ledger: ledger, Reader: reader, Now: time.Now, NewID: ownerRandomID,
		Refused: downloadRefusalReport(timedEventLog(os.Stderr, "query refused"), time.Now)}, Recovery: recovery, Routes: routes, Plans: plans,
		Workers: publicProjectionAdmission{&evidence.ProjectionWorkerAdmission{Cleanup: cleanup, Ledger: workers, Jobs: jobs, Audit: audit.projectionWorkerObjects(), Now: time.Now}}}
	// The peer adapter is retained by both native admissions. Configure it only
	// during startup, before any listener/goroutine can observe the pointer.
	peers, ok := d.Runtime.native.peers.(*mtls.NativePeerChecks)
	if !ok || peers == nil || peers.Projection != nil || ctx.Err() != nil || d.Runtime.started.Load() {
		return nil, mounts.ErrUnavailable
	}
	peers.Projection, peers.Origins = operations, origins
	d.shared.origins = origins
	dispatch.ProjectionCleanup = cleanup
	return service, nil
}
