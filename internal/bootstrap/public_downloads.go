package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	analysisapp "asservat.local/asservat/internal/application/analysis"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publicStopLedger splits stop restriction and the stop-write claim across
// their two logins, as migration 47 requires.
type publicStopLedger struct{ stop, writer *postgres.DownloadStops }

func (s publicStopLedger) StopDownload(ctx context.Context, i identity.Identity, id string, key artifact.Digest, request string) (evidence.DownloadStopSnapshot, error) {
	return s.stop.StopDownload(ctx, i, id, key, request)
}
func (s publicStopLedger) ClaimDownloadStopWrite(ctx context.Context, d artifact.DownloadStopDecision) (bool, error) {
	return s.writer.ClaimDownloadStopWrite(ctx, d)
}

// publicDownloads are the ADR-180 P4 services, composed after the owner
// runtime because native attachments bind its actual Pod and process.
type publicDownloads struct {
	coordinator evidence.ContextDownloadCoordinator
	native      ContextNativeDownloadServices
	downloads   *postgres.Downloads
	gate        authapp.ContextDownloadAuthority
	projection  *analysisapp.ContextProjectionService
}

func newPublicDownloads(ctx context.Context, d *OwnerDeployment, observer, probe *kube.PermissionClient, catalog publicCatalog, a publicAuditStore, closers *[]func()) (*publicDownloads, error) {
	in, pc := d.inputs, d.publicContext
	c, p := in.config, in.config.Public
	root, installation := c.PermissionRootID, c.InstallationID
	if p == nil || pc == nil || d.publicID == nil || d.Runtime == nil || d.workerIdentities == nil || !authorization.UUID(p.AuditStoreID) || !identity.Text(p.ArtifactKeyID, 128) || p.DownloadPlan.OutputLimit < 1 || p.DownloadPlan.ReadLimit < 1 || p.DownloadPlan.RequestLimit < 1 || p.DownloadPlan.DurationSeconds < 1 || p.DownloadPlan.DurationSeconds > 3600 {
		return nil, mounts.ErrUnavailable
	}
	g := postgres.DownloadTransactionGuards{Retention: d.shared.guards.Retention, Recovery: d.shared.guards.Recovery}
	sql := map[string]*pgxpool.Pool{}
	for _, purpose := range []string{"download-session", "download-source", "download-audit", "download-plan", "worker-config-read", "download-worker", "download-worker-audit", "worker-enrollment", "worker-enrollment-audit", "worker-enrollment-activate", "native-owner", "download-key-bind", "native-key-bind", "download-stop", "download-stop-writer", "download-stop-ack"} {
		pool, err := d.public.open(ctx, purpose)
		if err != nil {
			return nil, err
		}
		sql[purpose] = pool
	}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}

	// The download environment and the worker configuration are hub-held.
	ea, ep := capacityWorkerGuard(p.DownloadEnvironment.Guard)
	envGuard, err := kube.NewDownloadEnvironmentProtection(observer, probe, cfg.ConfigMapAdministration{Name: p.DownloadEnvironment.Guard.Name, SourceName: p.DownloadEnvironment.Source.Name, ControlNamespace: control, Administrators: ea}, ep)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	// ADR-204 decision 4: one derived path per cluster in the guarded catalog
	// read at start; a catalog change restarts the process (ADR-196).
	paths, err := downloadEnvironmentPaths(installation, c.ClusterID, p.DownloadEnvironment.Paths, p.DownloadEnvironment.PathTemplate, catalogTargets(catalog.catalog))
	if err != nil {
		return nil, err
	}
	environment, err := kube.NewDownloadEnvironmentSource(observer, envGuard, p.DownloadEnvironment.Source.Name, p.DownloadEnvironment.Source.UID, root, installation, paths)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	// Reuse one protected policy observation across download checks. The raw
	// reader remains independently current for privacy administration; this
	// download-only view does not cache recovery, processing or human authority.
	policies, err := authapp.NewDownloadPolicyObservations(environment, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	processing, err := d.public.open(ctx, "hub-metadata-read")
	if err != nil {
		return nil, err
	}
	processingReads, err := postgres.NewProcessingReads(ctx, processing, root, d.shared.guards.Recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	gate := authapp.ContextDownloadAuthority{RootID: root, Identities: d.publicID.download, Permissions: pc.permissions, Catalog: pc.catalog, Retention: pc.retention,
		Environment: authapp.CurrentDownloadEnvironment{RootID: root, InstallationID: installation, Policies: policies, Recovery: pc.recovery, Processing: processingReads, Now: time.Now}, Now: time.Now}

	makeDownloads := func(purpose string) (*postgres.Downloads, error) {
		return postgres.NewDownloads(ctx, sql[purpose], root, g)
	}
	downloads, err := makeDownloads("download-session")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	sources, err := makeDownloads("download-source")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	audits, err := makeDownloads("download-audit")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stops, err := postgres.NewDownloadStops(ctx, sql["download-stop"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stopWriter, err := postgres.NewDownloadStops(ctx, sql["download-stop-writer"], root, g.Recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stopAcks, err := postgres.NewDownloadStops(ctx, sql["download-stop-ack"], root, g.Recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	completions, err := postgres.NewDownloadStopLifecycles(ctx, sql["download-stop-writer"], root, g.Recovery)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	legacyStops, closedStops, err := a.stopObjects(p.AuditStoreID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stopObjects, err := evidence.NewHealthyDownloadStopObjects(legacyStops, closedStops, completions)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	stop := evidence.ContextDownloadStopCoordinator{Ledger: publicStopLedger{stops, stopWriter}, Acknowledgements: stopAcks, Objects: stopObjects, Now: time.Now}
	// ADR-200: a reservation refused for a stale binding re-arms the capacity
	// refresh demand, with the download-session credentials.
	refresh, err := postgres.NewCapacityRefreshDemands(ctx, sql["download-session"], root)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	coordinator := evidence.ContextDownloadCoordinator{RootID: root, InstallationID: installation, Routes: sources, Sources: sources, Authority: gate, Sessions: downloads, Refresh: refresh,
		Refused: downloadRefusalReport(eventLog(os.Stderr, "download refused"), time.Now)}

	wa, wp := capacityWorkerGuard(p.WorkerConfiguration.Guard)
	sourceObserver, sourceProbe, sourceControl, err := d.workerSourceClients(observer, probe, control, closers)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	workerGuard, err := kube.NewWorkerConfigurationProtection(sourceObserver, sourceProbe, cfg.WorkerAdministration{Name: p.WorkerConfiguration.Guard.Name, SourceName: p.WorkerConfiguration.Source.Name, ControlNamespace: sourceControl, Administrators: wa}, wp)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	workerSource, err := kube.NewWorkerConfigurationSource(sourceObserver, workerGuard, p.WorkerConfiguration.Source.Name, p.WorkerConfiguration.Source.UID, installation)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	observed, err := workerSource.ReadWorkerConfiguration(ctx)
	if errors.Is(err, kube.ErrWorkerUnconfigured) {
		// ADR-194 D1: no worker is configured. Downloads have no native runtime,
		// so prepare fails closed before any reservation; existing sessions are
		// still readable and stoppable. Configuring a worker takes a new process.
		coordinator.Plans = unconfiguredDownloadPlans{}
		return &publicDownloads{native: ContextNativeDownloadServices{Stop: stop}, downloads: downloads, gate: gate, coordinator: coordinator}, nil
	}
	if err != nil || !observed.Valid(time.Now()) {
		return nil, mounts.ErrUnavailable
	}
	profile := observed.Configuration.Profile
	// The hub-worker accepts and audits a revision; hub-api only serves one
	// that is already current in SQL (ADR-070). A later revision needs a restart.
	configuration, err := postgres.NewWorkerConfigurations(ctx, sql["worker-config-read"], installation, profile.ClusterID, profile.NamespaceUID, p.WorkerConfiguration.Source.UID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if _, err = configuration.CurrentWorkerConfiguration(ctx, profile); err != nil {
		return nil, mounts.ErrUnavailable
	}
	jobsClient := d.shared.workers[ownerNativeAPIKey{profile.ClusterID, profile.NamespaceUID}]
	if jobsClient == nil || profile.ClusterID != c.ClusterID {
		return nil, mounts.ErrUnavailable
	}
	jobs, err := kube.NewDownloadWorkerJobs(jobsClient, profile, configuration)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}

	makeWorkers := func(purpose string) (*postgres.DownloadWorkers, error) {
		return postgres.NewDownloadWorkers(ctx, sql[purpose], root, profile, g)
	}
	workers, err := makeWorkers("download-worker")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	workerAcks, err := makeWorkers("download-worker-audit")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	dispatch := &evidence.DownloadDispatcher{Ledger: workers, Jobs: jobs, Audit: a.workerObjects(), Acknowledgements: workerAcks, Authority: gate, CurrentAuthority: gate, Profile: profile, Now: time.Now}

	enrollment := func(purpose string) (*postgres.WorkerEnrollments, error) {
		return postgres.NewWorkerEnrollments(ctx, sql[purpose], root, profile, ownerRandomID)
	}
	ledger, err := enrollment("worker-enrollment")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	activation, err := enrollment("worker-enrollment-activate")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	enrollmentAcks, err := enrollment("worker-enrollment-audit")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	pki := p.WorkerPKI
	roots, _, err := mtls.OwnerTrustRoots(pki.Roots, time.Now())
	if err != nil || !ownerProviderName.MatchString(pki.Mount) || !ownerProviderName.MatchString(pki.Role) || !authorization.UUID(pki.IssuerEpoch) {
		return nil, mounts.ErrUnavailable
	}
	var issuer *kms.WorkerCertificateIssuer
	if d.providers != nil {
		if issuer = d.providers.WorkerIssuer(); issuer == nil {
			return nil, mounts.ErrUnavailable
		}
	} else if issuer, err = newPublicWorkerIssuer(ctx, d.publicFiles, in.config.KeyService.Endpoint, in.config.InstallationID, pki, roots, a); err != nil {
		return nil, err
	}
	enroll := evidence.WorkerEnrollmentCoordinator{CSR: mtls.EnrollmentProof{}, Ledger: ledger, Activation: activation, Audit: a.enrollmentObjects(), Acknowledgements: enrollmentAcks, Issuer: issuer, Now: time.Now}
	proofs := func(token evidence.DownloadPeerToken) (evidence.WorkerEnrollmentProofReader, error) {
		return kube.NewWorkerEnrollmentAttester(jobsClient, d.workerIdentities, token)
	}
	projectionLedger, err := postgres.NewProjectionEnrollments(ctx, sql["worker-enrollment"], root, profile, ownerRandomID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	projectionAcks, err := postgres.NewProjectionEnrollments(ctx, sql["worker-enrollment-audit"], root, profile, ownerRandomID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	projectionActivation, err := postgres.NewProjectionEnrollments(ctx, sql["worker-enrollment-activate"], root, profile, ownerRandomID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	enrollmentExchange := &evidence.AdmittedWorkerEnrollment{InstallationID: installation, Bindings: d.workerIdentities, Download: enroll, DownloadProofs: proofs,
		Projection: evidence.ProjectionEnrollmentCoordinator{CSR: mtls.EnrollmentProof{}, Ledger: projectionEnrollmentEffects{projectionLedger, projectionAcks, projectionActivation}, Audit: a.acquisitionObjects(), Issuer: issuer, Now: time.Now},
		ProjectionProofs: func(token evidence.DownloadPeerToken) (evidence.AcquisitionEnrollmentProofReader, error) {
			return kube.NewAcquisitionEnrollmentAttester(jobsClient, d.workerIdentities, token)
		}, Now: time.Now}

	native, err := postgres.NewNativeOwners(ctx, sql["native-owner"], root, profile, g)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	first, err := postgres.NewFirstContextNativeOperations(native)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	scope := authorization.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: p.ArtifactKeyID}
	prepKeys, err := postgres.NewDownloadKeys(ctx, sql["download-key-bind"], root, scope, g)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	windowKeys, err := postgres.NewNativeKeys(ctx, sql["native-key-bind"], root, profile, scope, g)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	preparations, err := postgres.NewFirstContextPreparations(downloads)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	responses, err := postgres.NewFirstContextResponses(downloads)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	windows, err := a.windowObjects(p.AuditStoreID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	services, err := NewContextNativeDownloadRuntime(d.Runtime, workers, preparations, configuration, first, responses, evidence.ContextNativeRuntimeConfig{
		Profile: profile, Dispatcher: dispatch, Sources: downloads, Authority: gate,
		Audit: a.downloadObjects(), Acknowledgements: audits,
		Native: evidence.NativeAttachmentConfig{KeyScope: scope, Fences: native, Origins: d.shared.origins, PreparationKeys: prepKeys, WindowKeys: windowKeys, Authority: gate, Now: time.Now, NewID: ownerRandomID},
		Now:    time.Now, NewID: ownerRandomID},
		evidence.DownloadResponseTransfer{Objects: windows, Audit: audits, NewResponseAuthority: func(ctx context.Context, scope artifact.DownloadScope) (evidence.CurrentDownloadAuthority, func(), error) {
			owned, err := gate.NewDownloadResponse(ctx, scope)
			if err != nil {
				return nil, nil, err
			}
			return owned, owned.Close, nil
		}}, stop)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	*closers = append(*closers, services.Runtime.Close)
	plans, err := postgres.NewContextDownloadPlans(ctx, sql["download-plan"], root, installation, profile, configuration, postgres.ContextDownloadPlanLimits{OutputLimit: p.DownloadPlan.OutputLimit, ReadLimit: p.DownloadPlan.ReadLimit, RequestLimit: int64(p.DownloadPlan.RequestLimit), Duration: time.Duration(p.DownloadPlan.DurationSeconds) * time.Second})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	coordinator.Plans = plans
	out := &publicDownloads{native: services, downloads: downloads, gate: gate, coordinator: coordinator}
	out.projection, err = newPublicProjection(ctx, d, environment, processingReads, profile, jobs, dispatch, sql["download-worker"], scope, a)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	// ADR-204 decision 9: this profile's hub-local workers enroll and run
	// their native path on the owner port. TLS client roots are the profile's
	// current issuer roots from the trust catalog, resolved per handshake.
	// It changes the runtime, so it is the last step that can fail.
	if err = d.Runtime.ServeAcquisitionWorkers(func(now time.Time) (*x509.CertPool, error) { return d.trust.IssuerRoots(profile, now) }, enrollmentExchange); err != nil {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

// workerSourceClients selects the clients that read the guarded worker
// profile source (ADR-204 decision 2). With exactly one pinned worker API in
// its own namespace, the source and guard live there: that API's client reads
// them and the namespace's separate probe token proves the guard. Without a
// worker API (the unconfigured installed layout), or with one pinned to the
// hub namespace itself, the hub namespace clients read it as before. More
// than one worker API names no single source namespace and is refused.
func (d *OwnerDeployment) workerSourceClients(observer, probe *kube.PermissionClient, control cfg.NamespaceRef, closers *[]func()) (*kube.PermissionClient, *kube.PermissionClient, cfg.NamespaceRef, error) {
	n := d.inputs.config.Native
	if n == nil || len(n.WorkerAPIs) == 0 {
		return observer, probe, control, nil
	}
	if len(n.WorkerAPIs) != 1 {
		return nil, nil, control, mounts.ErrUnavailable
	}
	a := n.WorkerAPIs[0]
	if a.Namespace.UID == control.UID {
		return observer, probe, control, nil
	}
	client := d.shared.workers[ownerNativeAPIKey{a.ClusterID, a.Namespace.UID}]
	if client == nil {
		return nil, nil, control, mounts.ErrUnavailable
	}
	workerProbe, closeHTTP, err := d.workerAPIClient(a, nativeKubernetesProbeTokenName(a))
	if err != nil {
		return nil, nil, control, mounts.ErrUnavailable
	}
	*closers = append(*closers, closeHTTP)
	return client, workerProbe, cfg.NamespaceRef{Name: a.Namespace.Name, UID: a.Namespace.UID}, nil
}

// unconfiguredDownloadPlans plans nothing: without a configured worker no
// download can be prepared (ADR-194 D1).
type unconfiguredDownloadPlans struct{}

func (unconfiguredDownloadPlans) ContextDownloadPlan(context.Context, artifact.DownloadScope) (evidence.ContextDownloadPlan, error) {
	return evidence.ContextDownloadPlan{}, artifact.ErrDownloadUnavailable
}

// newPublicWorkerIssuer reads the fixed worker-issue token once; rotating it
// takes effect through a new process.
func newPublicWorkerIssuer(ctx context.Context, files *providerInputs, endpoint, installation string, pki contracts.OwnerPublicWorkerPKI, roots *x509.CertPool, a publicAuditStore) (*kms.WorkerCertificateIssuer, error) {
	token, err := files.token(contracts.OwnerPublicWorkerIssueToken)(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(token)
	issuer, err := kms.NewWorkerCertificateIssuer(endpoint, strings.TrimSpace(string(token)), pki.Mount, pki.Role, installation, pki.IssuerEpoch, roots, a.keys, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return issuer, nil
}
