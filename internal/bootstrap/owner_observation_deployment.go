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
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
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

func NewOwnerObservationDeployment(ctx context.Context, files *os.Root, podUID string) (result *OwnerObservationDeployment, err error) {
	phase, purpose := startupProcessPreconditions, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &err)
	if ctx == nil || ctx.Err() != nil || files == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return nil, errors.Join(mounts.ErrUnavailable, err)
	}
	phase = startupInputs
	in, err := readOwnerInputs(ctx, files)
	if err != nil {
		return nil, err
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
	endpoints       *kube.OwnerEndpoints
	routes          *app.OwnerRoutes
	services        map[string]*app.OwnerEnrollmentCoordinator
	providers       *kms.InstalledOwnerProviderEffects
	// audit is the legacy static audit store and keys; empty with providers.
	audit publicAuditStore
}

// composeOwnerIdentity runs the installed identity startup unchanged: native
// identity proof before any SQL credential, verified identity pools, accepted
// configuration and the enrollment services. d owns every closer.
func composeOwnerIdentity(root, startup context.Context, files *os.Root, podUID string, d *OwnerDeployment, in *ownerInputs, governor *postgres.SQLConnectionGovernor, backend []string, phase *ownerStartupPhase, purpose *string) (parts *ownerIdentityParts, err error) {
	parts = &ownerIdentityParts{}
	defer func() {
		if err != nil && parts.stop != nil {
			parts.stop()
		}
	}()
	c := in.config
	activation := *c.Observation.Activation
	control := configuration.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	*phase = startupObserverClient
	// ADR-197 diagnostics: the shared observer's call count and transport
	// time, reported periodically by the owner deployment's Run.
	observerConfig := in.kubernetes("kube-observer.token")
	observerConfig.Wrap(d.observerStats.wrap)
	observer, err := kube.NewPermissionClient(observerConfig, c.ClusterID, control, time.Now)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupProbeClient
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	actors := make([]configuration.KubernetesActor, len(c.WorkloadGuard.Administrators))
	for i, a := range c.WorkloadGuard.Administrators {
		actors[i] = configuration.KubernetesActor{Kind: a.Kind, Name: a.Name}
	}
	g := c.WorkloadGuard
	schedulingLeases := make([]configuration.OwnerSchedulingLease, len(c.SchedulingLeases))
	for i, l := range c.SchedulingLeases {
		schedulingLeases[i] = configuration.OwnerSchedulingLease{Lease: l.Lease, ServiceAccount: l.ServiceAccount}
	}
	configurationProbes := make([]configuration.OwnerConfigurationProbe, len(c.ConfigurationProbes))
	for i, p := range c.ConfigurationProbes {
		configurationProbes[i] = configuration.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount}
	}
	var initialHistory *configuration.OwnerInitialHistoryProbe
	if p := c.InitialHistoryProbe; p != nil {
		initialHistory = &configuration.OwnerInitialHistoryProbe{Namespace: configuration.NamespaceRef{Name: p.Namespace.Name, UID: p.Namespace.UID}, ServiceAccount: p.ServiceAccount.Name, ServiceAccountUID: p.ServiceAccount.UID, Configuration: p.Configuration}
	}
	*phase = startupStartInputs
	starts, err := ownerDeploymentStarts(c.APIContextStarts)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupCapacityInputs
	capacityProbe, err := ownerDeploymentCapacityProbe(c.CapacityProbe)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupWorkloadGuard
	guard, err := kube.NewOwnerWorkloadProtection(observer, probe, configuration.OwnerWorkloadAdministration{Name: g.Name, Deployment: activation.Input.Deployment.Name, DeploymentUID: activation.Input.Deployment.UID, ControlNamespace: control, Administrators: actors, ConfigurationProbes: configurationProbes, SchedulingLeases: schedulingLeases, InitialHistoryProbe: initialHistory, APIContextStarts: starts, CapacityProbe: capacityProbe}, kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}

	*phase = startupMountedIdentity
	mounted, manifest, err := readSelectedOwnerIdentityProviders(startup, files, c)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	defer func() {
		for _, b := range mounted {
			clear(b)
		}
	}()
	*phase = startupIdentityReader
	identityReader, err := kube.NewInstalledOwnerIdentityReader(observer, guard, c, activation, mountedOwnerPodToken{in}, podUID)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	*phase = startupNativeIdentity
	identityUntil, err := identityReader.VerifyStartup(startup, manifest, mounted)
	if err != nil || !time.Now().Before(identityUntil) {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	if c.Public != nil && c.ProviderAuthentication != nil {
		// ADR-194: the installed public root must be the referenced immutable
		// product projection before any public credential is opened.
		*phase = startupPublicProjection
		check, end := context.WithDeadline(startup, identityUntil)
		public, e := readPublicProjectionFiles(check, d.publicFiles.files)
		if e == nil {
			e = identityReader.VerifyPublicProjection(check, c.Public.RuntimeProjection, public)
		}
		for _, b := range public {
			clear(b)
		}
		end()
		if e != nil {
			return parts, errors.Join(mounts.ErrUnavailable, e)
		}
	}
	// SQL credentials are not used until the exact current original projection,
	// live Pod/token and native guard have been independently established. Every
	// role check retains that proof's original deadline, never a new interval.
	verified, stopVerified := context.WithDeadline(startup, identityUntil)
	parts.verified, parts.stop = verified, stopVerified
	pools := map[string]*pgxpool.Pool{}
	users := map[string]bool{}
	// ADR-184: a promoted hub-api also opens its backend pools here, under the
	// same name, SCRAM, governor and manifest checks as the identity pools.
	roles := append([]string{"enrollment", "audit", "activation", "registry"}, backend...)
	for _, role := range roles {
		*purpose = role
		*phase = startupSqlCredential
		c, err := in.sqlConfig(verified, "sql-"+role+".json")
		if err != nil || c == nil || users[c.ConnConfig.User] {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		*phase = startupSqlRoleName
		expected, known := postgres.OwnerIdentityRoleName(in.config.InstallationID, role)
		if !known || c.ConnConfig.User != expected {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		c.MaxConns, c.MinConns = 1, 0
		c.ConnConfig.RequireAuth = "scram-sha-256"
		users[c.ConnConfig.User] = true
		// A promoted installed owner governs its identity pools too (ADR-177).
		if governor != nil && governor.Govern(c, true) != nil {
			return parts, mounts.ErrUnavailable
		}
		*phase = startupSqlPool
		pool, err := pgxpool.NewWithConfig(verified, c)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		pools[role] = pool
		d.closers = append(d.closers, pool.Close)
		*phase = startupSqlRoleProof
		if err = postgres.VerifyOwnerIdentityCredential(verified, pool, manifest, role); err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
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
	*phase = startupOriginalPool
	pool := current.Configuration.Pool
	if pool.Deployment != activation.Input.Deployment.Name || pool.DeploymentUID != activation.Input.Deployment.UID || pool.ServiceAccount != activation.Input.ServiceAccount.Name || pool.AccountUID != activation.Input.ServiceAccount.UID || verified.Err() != nil {
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
	*phase = startupEndpoints
	endpoints, err := kube.NewOwnerEndpoints(observer, pool)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	routes := &app.OwnerRoutes{Configurations: configs, Endpoints: endpoints, Now: time.Now}
	var audits auditapp.OwnerEnrollmentWriter
	issuers := map[string]*kms.OwnerCertificateIssuer{}
	if c.ProviderAuthentication != nil {
		*phase = startupProviderEffects
		parts.providers, err = kms.NewInstalledOwnerProviderEffects(root, c, files, identityReader, configs, current.Configuration)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		*phase = startupProviderAudit
		auditObjects, e := newInstalledOwnerEnrollmentAudit(c, parts.providers)
		if e != nil {
			return parts, errors.Join(mounts.ErrUnavailable, e)
		}
		audits = auditObjects
		d.closers = append(d.closers, auditObjects.Close)
		issuers["server"], issuers["client"] = parts.providers.ServerIssuer(), parts.providers.ClientIssuer()
	} else {
		*phase = startupAuditHttp
		h, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
		if err != nil {
			return parts, err
		}
		d.closers = append(d.closers, h.CloseIdleConnections)
		*phase = startupAuditSealer
		seal, err := kms.NewSealerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-wrap.token"), h)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		d.closers = append(d.closers, seal.Close)
		*phase = startupAuditOpener
		open, err := kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-unwrap.token"), h)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		d.closers = append(d.closers, open.Close)
		*phase = startupAuditStoreHttp
		storageHTTP, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
		if err != nil {
			return parts, err
		}
		d.closers = append(d.closers, storageHTTP.CloseIdleConnections)
		*phase = startupAuditStore
		store, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in.providerInputs}, storageHTTP)
		if err != nil {
			return parts, errors.Join(mounts.ErrUnavailable, err)
		}
		d.closers = append(d.closers, store.Close)
		audits = &objectstore.OwnerEnrollmentAuditObjects{Store: store, Seal: seal, Open: open}
		parts.audit = publicAuditStore{store: store, seal: seal, open: open, keys: h}
		for _, usage := range []string{"server", "client"} {
			role := c.KeyService.ServerRole
			if usage == "client" {
				role = c.KeyService.ClientRole
			}
			*phase, *purpose = startupCertificateIssuer, usage
			issuer, e := kms.NewOwnerCertificateIssuerForPoolWithTokenSource(c.KeyService.Endpoint, c.KeyService.PKIMount, role, pool, usage, roots, in.token("owner-"+usage+"-sign.token"), h, time.Now)
			if e != nil {
				return parts, errors.Join(mounts.ErrUnavailable, e)
			}
			d.closers = append(d.closers, issuer.Close)
			issuers[usage] = issuer
		}
	}
	*purpose = "none"
	*phase = startupPeerVerifier
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, pool, time.Now)
	if err != nil {
		return parts, errors.Join(mounts.ErrUnavailable, err)
	}
	services := map[string]*app.OwnerEnrollmentCoordinator{}
	for _, usage := range []string{"server", "client"} {
		issuer := issuers[usage]
		services[usage] = &app.OwnerEnrollmentCoordinator{Verifier: verifier, Proofs: proofs, Ledger: ledgers["enrollment"], Activation: ledgers["activation"], Audit: audits, Acknowledgements: ledgers["audit"], Issuer: issuer, Now: time.Now}
	}
	parts.observer, parts.probe, parts.guard, parts.pools, parts.configs, parts.pool, parts.roots = observer, probe, guard, pools, configs, pool, roots
	parts.ledgers, parts.proofs, parts.endpoints, parts.routes, parts.services = ledgers, proofs, endpoints, routes, services
	return parts, nil
}

// readPublicProjectionFiles reads the product projection's fixed keys from the
// mounted public root: one login per hub purpose, the manifest and the audit
// keys. The operator Secret's keys in the same root are not read here.
func readPublicProjectionFiles(ctx context.Context, root *os.Root) (map[string][]byte, error) {
	names := []string{contracts.PublicRuntimeCredentialManifestFile, contracts.PublicAuditKeysFile}
	for _, purpose := range contracts.PublicRuntimeHubRolePurposes() {
		names = append(names, "sql-public-"+purpose+".json")
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		b, err := mounts.Read(ctx, root, name, contracts.PublicRuntimeRoleMaxBytes)
		if err != nil {
			for _, v := range out {
				clear(v)
			}
			return nil, mounts.ErrUnavailable
		}
		out[name] = b
	}
	return out, nil
}
