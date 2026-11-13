package bootstrap

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	configuration "asservat.local/asservat/internal/domain/configuration"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This loader shares only the original provider/proof constructors with owner
// identity setup. It opens exactly the four owner-identity SQL facets and never
// calls the full deployment loader or reads routing/native/worker projections.
// Optional backend/public projections are neither opened nor activated here.
type OwnerObservationDeployment struct {
	Runtime   *OwnerObservationRuntime
	base      *OwnerDeployment
	providers *kms.InstalledOwnerProviderEffects
	mu        sync.Mutex
	closed    bool
	running   bool
	owners    sync.WaitGroup
	once      sync.Once
	closeErr  error
}

func NewOwnerObservationDeployment(ctx context.Context, files *os.Root, podUID string) (*OwnerObservationDeployment, error) {
	if ctx == nil || files == nil {
		return nil, mounts.ErrUnavailable
	}
	in, err := readOwnerInputs(ctx, files)
	if err != nil {
		return nil, ownerStartupError(startupInputs, "none", err)
	}
	return newOwnerObservationDeployment(ctx, files, podUID, in)
}

func newOwnerObservationDeployment(ctx context.Context, files *os.Root, podUID string, in *ownerInputs) (result *OwnerObservationDeployment, err error) {
	phase, purpose := startupProcessPreconditions, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &err)
	if ctx == nil || ctx.Err() != nil || files == nil || in == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	phase = startupDeploymentMode
	if in.config.Observation == nil || in.config.Native != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	root, cancel := context.WithCancel(ctx)
	// The base owns provider pools/HTTP clients only. Its Runtime and Router stay
	// nil; its Run method is never used as an observation-mode fallback.
	d := &OwnerDeployment{inputs: in, root: root, cancel: cancel}
	d.closers = append(d.closers, in.closeHTTP)
	out := &OwnerObservationDeployment{base: d}
	complete := false
	defer func() {
		if !complete {
			out.Close()
		}
	}()
	startup, end := context.WithTimeout(root, 30*time.Second)
	defer end()
	c := in.config
	var parts *ownerIdentityParts
	parts, err = composeOwnerIdentity(root, startup, files, podUID, d, in, nil, nil, &phase, &purpose)
	// Provider effects created before a failure still need their joined close.
	out.providers = parts.providers
	if err != nil {
		return nil, err
	}
	defer parts.stop()
	observer, guard, pool, configs, verified := parts.observer, parts.guard, parts.pool, parts.configs, parts.verified
	services, ledgers, proofs, routes := parts.services, parts.ledgers, parts.proofs, parts.routes

	phase = startupObservationInputs
	pin, peers, err := ownerObservationConfig(c, pool)
	if err != nil {
		return nil, err
	}
	phase = startupObservationWorkload
	workload, err := kube.NewOwnerObservationWorkload(observer, guard, pin)
	if err != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	phase = startupObservationRuntime
	out.Runtime, err = newOwnerObservationRuntime(root, verified, OwnerObservationRuntimeConfig{Pin: pin, PodUID: podUID, Configuration: configs, ServerEnrollment: services["server"], ClientEnrollment: services["client"], Registry: ledgers["registry"], Proofs: proofs, Routes: routes, Protection: guard, Workloads: workload, Peers: peers, Connections: c.Connections, Concurrency: c.Concurrency,
		Local: ownerLocalCapacity(in, observer, guard, c, podUID, c.Concurrency, &d.closers)})
	if err != nil || verified.Err() != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	complete = true
	return out, nil
}

// Close disables admission and cancels first. It retains every dependency until
// the admitted Run and its native/readiness/provider children have actually
// joined. In particular, a bounded provider Close failure cannot release files
// or SQL pools still owned by a cancelled operation.
func (d *OwnerObservationDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		if d.base != nil && d.base.cancel != nil {
			d.base.cancel()
		}
		if d.Runtime != nil {
			d.Runtime.Close()
		}
		d.owners.Wait()
		if d.providers != nil {
			d.closeErr = d.providers.CloseAndJoin(context.Background())
		}
		if d.base != nil {
			d.base.Close()
		}
	})
}
func (d *OwnerObservationDeployment) Run(listener net.Listener) (result error) {
	phase, purpose := startupRunPreconditions, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &result)
	if d == nil || d.Runtime == nil || d.base == nil || d.base.root == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	d.mu.Lock()
	if d.closed || d.running || d.base.root.Err() != nil {
		d.mu.Unlock()
		return mounts.ErrUnavailable
	}
	d.running = true
	d.owners.Add(1)
	d.mu.Unlock()
	defer func() {
		// The body has already joined both children. Release this registration
		// before Close waits, including when an external Close owns shutdown.
		d.owners.Done()
		d.Close()
		if d.closeErr != nil {
			phase = startupProviderClose
			result = d.closeErr
		}
	}()
	if d.providers == nil {
		phase = startupRuntimeSupervisor
		return d.Runtime.Run(listener)
	}
	phase = startupProviderProof
	if _, err := d.providers.Current(d.base.root); err != nil {
		_ = listener.Close()
		return err
	}
	phase = startupProviderPrime
	if err := d.providers.Prime(d.base.root); err != nil {
		_ = listener.Close()
		return err
	}
	providerDone := make(chan error, 1)
	runtimeDone := make(chan error, 1)
	go func() { providerDone <- d.providers.Run(d.base.root) }()
	go func() { runtimeDone <- d.Runtime.Run(listener) }()
	select {
	case result = <-runtimeDone:
		phase = startupRuntimeSupervisor
		d.base.cancel()
		d.Runtime.Close()
		<-providerDone
	case result = <-providerDone:
		phase = startupProviderSupervisor
		d.base.cancel()
		d.Runtime.Close()
		<-runtimeDone
	}
	return result
}

// ownerIdentityParts is the identity layer of an observation-mode or promoted
// installed owner (ADR-182): verified identity pools, accepted configuration,
// enrollment services and the provider effects or legacy static keys.
type ownerIdentityParts struct {
	observer, probe *kube.PermissionClient
	guard           *kube.OwnerWorkloadProtection
	verified        context.Context
	stop            context.CancelFunc
	pools           map[string]*pgxpool.Pool
	configs         *postgres.OwnerConfigurations
	pool            fleetvalue.OwnerPool
	roots           *x509.CertPool
	ledgers         map[string]*postgres.OwnerEnrollments
	proofs          *kube.OwnerEnrollmentAttester
	// readinessProofs is the readiness loop's own attester (ADR-173); nil
	// on the legacy static layout, which uses proofs.
	readinessProofs *kube.OwnerEnrollmentAttester
	endpoints       *kube.OwnerEndpoints
	routes          *app.OwnerRoutes
	services        map[string]*app.OwnerEnrollmentCoordinator
	providers       *kms.InstalledOwnerProviderEffects
	// audit is the legacy static audit store and keys; empty with providers.
	audit publicAuditStore
}

// composeOwnerIdentity opens the owner's SQL credential, reads the accepted
// owner configuration and builds the enrollment services and provider
// effects. Helm-native installation (ADR-328): the mounted inputs are
// trusted as Kubernetes delivers them; no installation journal, launch
// receipt, projection identity or admission guard is verified. d owns every
// closer.
func composeOwnerIdentity(root, startup context.Context, files *os.Root, podUID string, d *OwnerDeployment, in *ownerInputs, governor *postgres.SQLConnectionGovernor, backend []string, phase *ownerStartupPhase, purpose *string) (parts *ownerIdentityParts, err error) {
	parts = &ownerIdentityParts{}
	defer func() {
		if err != nil && parts.stop != nil {
			parts.stop()
		}
	}()
	c := in.config
	if c.ProviderAuthentication == nil || !authorization.UUID(podUID) {
		return parts, mounts.ErrUnavailable
	}
	control := configuration.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	*phase = startupObserverClient
	// ADR-197 diagnostics: the shared observer's call count and transport
	// time, reported periodically by the owner deployment's Run.
	observerConfig := in.kubernetes(contracts.HubAPIKubernetesTokenFile)
	observerConfig.Wrap(d.observerStats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	verified, stopVerified := context.WithCancel(startup)
	parts.verified, parts.stop = verified, stopVerified
	pools := map[string]*pgxpool.Pool{}
	// ADR-184: a promoted hub-api also opens its backend pools here, under the
	// same name, SCRAM and governor checks as the identity pools.
	for _, role := range contracts.OwnerIdentityRolePurposes() {
		*purpose = role
		*phase = startupSqlCredential
		config, err := in.sqlConfig(verified, "sql-"+role+".json")
		if err != nil || config == nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		*phase = startupSqlRoleName
		expected, known := postgres.OwnerIdentityRoleName(c.InstallationID, role)
		if !known || config.ConnConfig.User != expected {
			return parts, mounts.ErrUnavailable
		}
		config.MaxConns, config.MinConns = contracts.OwnerIdentityPoolConnections, 0
		config.ConnConfig.RequireAuth = "scram-sha-256"
		if governor != nil && governor.Govern(config, true) != nil {
			return parts, mounts.ErrUnavailable
		}
		*phase = startupSqlPool
		pool, err := pgxpool.NewWithConfig(verified, config)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		pools[role] = pool
		d.closers = append(d.closers, pool.Close)
		*phase = startupSqlRoleProof
		if err = postgres.VerifySessionRole(verified, pool, expected); err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
	}
	// Typed identity and backend adapters share this process credential. The
	// pool is opened, verified and closed once, with six physical slots.
	for _, duty := range []string{"enrollment", "audit", "activation", "registry", "routing", "native-read"} {
		pools[duty] = pools["owner-runtime"]
	}
	*purpose = "none"
	*phase = startupConfigurationReader
	configs, err := postgres.NewOwnerConfigurations(verified, pools["registry"], c.InstallationID, c.ClusterID, c.Namespace.UID, c.ConfigurationUID)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupAcceptedConfiguration
	current, err := configs.ReadOwnerConfiguration(verified)
	if err != nil || !current.Valid(time.Now()) || current.Configuration.Suspended || current.Configuration.Pool.Namespace != c.Namespace.Name {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	pool := current.Configuration.Pool
	*phase = startupWorkloadGuard
	administration := configuration.OwnerWorkloadAdministration{Deployment: pool.Deployment, DeploymentUID: pool.DeploymentUID, ControlNamespace: control}
	guard, err := kube.NewOwnerWorkloadProtection(observer, nil, administration, kube.GuardPin{})
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupIssuerRoots
	roots, _, err := mtls.OwnerTrustRoots(current.Configuration.IssuerRoots, time.Now())
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	ledgers := map[string]*postgres.OwnerEnrollments{}
	for _, role := range []string{"enrollment", "audit", "activation", "registry"} {
		*purpose = role
		*phase = startupEnrollmentLedger
		l, err := postgres.NewOwnerEnrollments(verified, pools[role], c.InstallationID, c.ClusterID, c.Namespace.UID, c.ConfigurationUID, ownerRandomID)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		ledgers[role] = l
	}
	*purpose = "none"
	*phase = startupEnrollmentAttester
	proofs, err := kube.NewOwnerEnrollmentAttester(observer, configs, guard, mountedOwnerPodToken{in})
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	// ADR-173: the readiness loop gets its own client and attester so its
	// proofs never queue request paths behind it.
	if parts.readinessProofs, err = ownerReadinessProofs(in, c.ClusterID, control, administration, configs, &d.readinessStats); err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupEndpoints
	endpoints, err := kube.NewOwnerEndpoints(observer, pool)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	routes := &app.OwnerRoutes{Configurations: configs, Endpoints: endpoints, Now: time.Now}
	*phase = startupProviderEffects
	parts.providers, err = kms.NewInstalledOwnerProviderEffects(root, c, files, configs, current.Configuration)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupProviderAudit
	audits, err := newInstalledOwnerEnrollmentAudit(c, parts.providers)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	d.closers = append(d.closers, audits.Close)
	issuers := map[string]*kms.OwnerCertificateIssuer{"server": parts.providers.ServerIssuer(), "client": parts.providers.ClientIssuer()}
	*phase = startupPeerVerifier
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, pool, time.Now)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	services := map[string]*app.OwnerEnrollmentCoordinator{}
	for _, usage := range []string{"server", "client"} {
		services[usage] = &app.OwnerEnrollmentCoordinator{Verifier: verifier, Proofs: proofs, Ledger: ledgers["enrollment"], Activation: ledgers["activation"], Audit: audits, Acknowledgements: ledgers["audit"], Issuer: issuers[usage], Now: time.Now}
	}
	parts.observer, parts.guard, parts.pools, parts.configs, parts.pool, parts.roots = observer, guard, pools, configs, pool, roots
	parts.ledgers, parts.proofs, parts.endpoints, parts.routes, parts.services = ledgers, proofs, endpoints, routes, services
	return parts, nil
}

// ownerReadinessProofs builds the readiness loop's enrollment attester on its
// own observer client, with the same workload administration.
func ownerReadinessProofs(in *ownerInputs, cluster string, control configuration.NamespaceRef, administration configuration.OwnerWorkloadAdministration, configs *postgres.OwnerConfigurations, stats *regionalAPIStats) (*kube.OwnerEnrollmentAttester, error) {
	observerConfig := in.kubernetes(contracts.HubAPIKubernetesTokenFile)
	observerConfig.Wrap(stats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, cluster, control, time.Now)
	if err != nil {
		return nil, err
	}
	guard, err := kube.NewOwnerWorkloadProtection(observer, nil, administration, kube.GuardPin{})
	if err != nil {
		return nil, err
	}
	return kube.NewOwnerEnrollmentAttester(observer, configs, guard, mountedOwnerPodToken{in})
}
