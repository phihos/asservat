package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	configuration "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OwnerDeployment composes only the private owner subsystem. Installation and
// continuously reconciled audited configuration/recovery are independent; this
// process cannot initialize them, accept profiles or clear RecoveryBlocked.
type OwnerDeployment struct {
	observerStats, operationStats regionalAPIStats
	Runtime                       *OwnerRuntime
	Router                        *evidence.WorkerEnrollmentRouter
	inputs                        *ownerInputs
	trust                         *mtls.WorkerTrustCatalog
	root                          context.Context
	cancel                        context.CancelFunc
	closers                       []func()
	mu                            sync.Mutex
	closed                        bool
	running                       bool
	owners                        sync.WaitGroup
	once                          sync.Once
	catalogDigest                 [32]byte
	// public holds the ADR-180 public purpose pools, identity and context
	// services; all nil without Public. shared is the native composition's
	// retention topology and effect guards, reused by the public layer.
	public          *publicPools
	publicID        *publicIdentity
	publicContext   *publicContext
	publicDownloads *publicDownloads
	publicHandler   http.Handler
	shared          publicShared
	// ADR-182: backend and public input roots (the owner root in the legacy
	// layout) and, in the installed layout, the provider effects.
	backend, publicFiles *providerInputs
	providers            *kms.InstalledOwnerProviderEffects
}

func ownerRandomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// NewOwnerDeployment borrows an installation-owned mount root. The caller
// retains it until Run/Close has stopped all use. No path comes from a request.
func NewOwnerDeployment(ctx context.Context, files *os.Root, podUID string) (result *OwnerDeployment, err error) {
	// The innermost phase names a startup failure (ADR-194 qualification).
	phase, purpose := startupProcessPreconditions, "none"
	defer ownerStartupAnnotate(&phase, &purpose, &err)
	if ctx == nil || ctx.Err() != nil || files == nil || !authorization.UUID(podUID) || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	phase = startupInputs
	in, err := readOwnerInputs(ctx, files)
	if err != nil {
		return nil, err
	}
	// ADR-182: an identity-only installed owner is the observation deployment;
	// only a promoted installed input (with Native) reaches this composition.
	installed := in.config.Observation != nil
	if installed && in.config.Native == nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	d := &OwnerDeployment{inputs: in, root: root, cancel: cancel}
	d.closers = append(d.closers, in.closeHTTP)
	complete := false
	defer func() {
		if !complete {
			d.Close()
		}
	}()
	startup, end := context.WithTimeout(root, 30*time.Second)
	defer end()
	// ADR-182: the installed layout reads backend and public inputs only from
	// their own projection roots; the legacy layout keeps one root.
	d.backend, d.publicFiles = in.providerInputs, in.providerInputs
	if installed {
		if d.backend, err = d.projectionInputs(contracts.OwnerObservationProjectionRoot); err != nil {
			return nil, err
		}
		if in.config.Public != nil {
			if d.publicFiles, err = d.projectionInputs(contracts.OwnerPublicProjectionRoot); err != nil {
				return nil, err
			}
		}
	}
	backendRoles := []string{"routing"}
	if in.config.Native != nil {
		backendRoles = append(backendRoles, "native-read")
	}
	// ADR-177: the process holds at most the per-replica allowance of physical
	// connections; the owner pools keep dedicated slots.
	hot := (4 + len(backendRoles)) * int(in.config.Postgres.MaxConnections)
	if installed {
		// ADR-184: every installed owner pool is an identity purpose with one
		// connection per process.
		hot = 4 + len(backendRoles)
	}
	if in.config.Public != nil {
		hot += len(hubAPIHotPurposes)
	}
	governor, err := postgres.NewSQLConnectionGovernor(contracts.SQLConnectionsPerHubReplica, hot)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if in.config.Public != nil {
		phase = startupPublicPools
		manifest, err := readPublicRuntimeManifest(startup, in, d.publicFiles)
		if err != nil {
			return nil, err
		}
		d.public = &publicPools{in: d.publicFiles, manifest: manifest, governor: governor}
		d.closers = append(d.closers, d.public.Close)
	}
	var parts *ownerIdentityParts
	if installed {
		phase = startupProcessPreconditions
		parts, err = composeOwnerIdentity(root, startup, files, podUID, d, in, governor, backendRoles, &phase, &purpose)
		if parts != nil {
			d.providers = parts.providers
		}
		if err != nil {
			return nil, err
		}
		defer parts.stop()
		if in.config.Public != nil {
			if parts.audit, err = d.installedAuditStore(parts.providers); err != nil {
				return nil, err
			}
		}
	} else if parts, err = legacyOwnerIdentity(startup, d, in, governor); err != nil {
		return nil, err
	}
	pools := parts.pools
	for _, role := range backendRoles {
		if installed {
			break // opened and verified with the identity pools (ADR-184)
		}
		c, err := d.backend.sqlConfig(startup, "sql-"+role+".json")
		if err != nil || c == nil || governor.Govern(c, true) != nil {
			return nil, mounts.ErrUnavailable
		}
		pool, err := pgxpool.NewWithConfig(startup, c)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		pools[role] = pool
		d.closers = append(d.closers, pool.Close)
	}
	c := in.config
	observer, probe, guard, pool, configs, ledgers, proofs, routes, services := parts.observer, parts.probe, parts.guard, parts.pool, parts.configs, parts.ledgers, parts.proofs, parts.routes, parts.services
	phase = startupWorkerRouting
	reader, err := postgres.NewWorkerRouting(startup, pools["routing"], c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.trust, err = mtls.NewWorkerTrustCatalog(c.InstallationID, nil)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if _, err = d.refreshWorkerTrust(startup); err != nil {
		return nil, err
	}
	d.Router, err = evidence.NewWorkerEnrollmentRouter(root, c.InstallationID, reader, time.Now, c.Concurrency)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	var nativeConfig *OwnerNativeRuntimeConfig
	if (c.Native == nil) != (pool.NativePort == 0) {
		return nil, mounts.ErrUnavailable
	}
	// ADR-196 decision 7: the catalog is read before the native configuration,
	// which unions the joined slots' topology pins with the input's.
	var catalog publicCatalog
	if c.Public != nil {
		phase = startupClusterCatalog
		if catalog, err = readPublicClusterCatalog(startup, c, observer, probe); err != nil {
			return nil, err
		}
	}
	if c.Native != nil {
		phase = startupNativeConfiguration
		nativeConfig, err = d.nativeConfiguration(startup, pools["native-read"], observer, catalog.catalog.Clusters)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	if c.Public != nil {
		var closers []func()
		phase = startupPublicIdentity
		// ADR-173: identity and browser settings reads (three calls per
		// identity resolution, about 39 per capture preview) get their own
		// client rather than queuing behind the owner's other observers.
		identityObserver, e := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), c.ClusterID, configuration.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, time.Now)
		if e != nil {
			return nil, mounts.ErrUnavailable
		}
		d.publicID, closers, err = newPublicIdentity(startup, in, d.publicFiles, d.providers, identityObserver, d.public)
		d.closers = append(d.closers, closers...)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		closers = nil
		phase = startupPublicContext
		d.publicContext, err = newPublicContext(startup, in, d.publicFiles, d.providers, d.public, observer, probe, d.shared, catalog, parts.audit, &closers)
		d.closers = append(d.closers, closers...)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		nativeConfig.ContextStarts = d.publicContext.starts
	}
	// ADR-190 decision 4: an installed promoted owner keeps serving the
	// observation handler set, now beside the native handler on its port.
	phase = startupOwnerRuntime
	var observation *OwnerObservationServingConfig
	var operation *OwnerOperationConfig
	if installed {
		phase = startupObservationInputs
		pin, peers, e := ownerObservationConfig(c, pool)
		if e != nil {
			return nil, e
		}
		phase = startupObservationWorkload
		workload, e := kube.NewOwnerObservationWorkload(observer, guard, pin)
		if e != nil {
			return nil, errors.Join(mounts.ErrUnavailable, e)
		}
		observation = &OwnerObservationServingConfig{Pin: pin, Workloads: workload, Peers: peers, Local: ownerLocalCapacity(in, observer, guard, c, podUID, c.Concurrency, &d.closers)}
		if c.Public != nil {
			phase = startupOperationInputs
			if operation, err = d.ownerOperationConfig(startup, in, c, pin, catalog, guard, ledgers["registry"]); err != nil {
				return nil, err
			}
		}
	}
	phase = startupOwnerRuntime
	var readinessProofs app.OwnerEnrollmentProofReader
	if parts.readinessProofs != nil {
		readinessProofs = parts.readinessProofs
	}
	d.Runtime, err = NewOwnerRuntime(root, OwnerRuntimeConfig{Pool: pool, PodUID: podUID, SourceUID: c.ConfigurationUID, Configuration: configs, ServerEnrollment: services["server"], ClientEnrollment: services["client"], Registry: ledgers["registry"], Proofs: proofs, ReadinessProofs: readinessProofs, Routes: routes, Protection: guard, Requests: func(b value.OwnerBinding) (evidence.WorkerOwnerEnrollment, error) {
		return &evidence.WorkerRequestOwners{Router: d.Router, PodUID: b.PodUID, ProcessEpoch: b.ProcessEpoch}, nil
	}, WorkerTrust: d.trust, Workers: reader, Locators: reader, Connections: c.Connections, Concurrency: c.Concurrency, Native: nativeConfig, Observation: observation, Operation: operation})
	if err != nil || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	if c.Public != nil {
		var closers []func()
		a := parts.audit
		phase = startupPublicDownloads
		d.publicDownloads, err = newPublicDownloads(startup, d, observer, probe, a, &closers)
		if err == nil {
			phase = startupPublicHandler
			d.publicHandler, err = newPublicHandler(startup, d, a, &app.OwnerAuthenticator{Registry: ledgers["registry"], Routes: routes, Protection: guard, Now: time.Now}, &closers)
		}
		d.closers = append(d.closers, closers...)
		if err != nil || startup.Err() != nil {
			return nil, mounts.ErrUnavailable
		}
	}
	complete = true
	return d, nil
}

func (d *OwnerDeployment) refreshWorkerTrust(ctx context.Context) ([32]byte, error) {
	var zero [32]byte
	b, err := mounts.Read(ctx, d.backendInputs().files, "worker-controls.json", 16<<20)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	digest := sha256.Sum256(b)
	if digest == d.catalogDigest {
		return digest, nil
	}
	wire, err := contracts.DecodeOwnerWorkerTrust(bytes.NewReader(b))
	if err != nil || wire.Format != contracts.OwnerWorkerTrustFormat || wire.Controls == nil || len(wire.Controls) > 256 {
		return zero, mounts.ErrUnavailable
	}
	if err = d.trust.Replace(wire.Controls); err != nil {
		return zero, mounts.ErrUnavailable
	}
	d.catalogDigest = digest
	return digest, nil
}

func (d *OwnerDeployment) Close() {
	if d == nil {
		return
	}
	d.once.Do(func() {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		if d.cancel != nil {
			d.cancel()
		}
		// Disable both owners before joining either. Runtime.Run owns its
		// readiness/native children; the router also admits independent control
		// registrations and retains busy deliveries through their final close.
		if d.Router != nil {
			d.Router.Close()
		}
		if d.Runtime != nil {
			d.Runtime.Close()
		}
		d.owners.Wait()
		if d.Router != nil {
			d.Router.CloseAndJoin()
		}
		// Provider lifetimes join before the files and pools they borrow close.
		if d.providers != nil {
			_ = d.providers.CloseAndJoin(context.Background())
		}
		for i := len(d.closers) - 1; i >= 0; i-- {
			d.closers[i]()
		}
	})
}

// Run owns the listener on acceptance. A missing/malformed current catalog
// stops the subsystem; retaining an earlier snapshot is not a refresh success.
func (d *OwnerDeployment) Run(listener net.Listener, additional ...net.Listener) error {
	if d == nil || d.Runtime == nil || d.root == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	d.mu.Lock()
	if d.closed || d.running || d.root.Err() != nil {
		d.mu.Unlock()
		return mounts.ErrUnavailable
	}
	d.running = true
	d.owners.Add(1)
	d.mu.Unlock()
	defer func() {
		// The body has joined Runtime.Run. Release this registration before
		// shared shutdown waits, including when external Close owns it.
		d.owners.Done()
		d.Close()
	}()
	// ADR-182: an installed owner's provider effects are primed before any
	// listener and supervised with the runtime; either ending stops both.
	var providerDone chan error
	if d.providers != nil {
		if err := d.providers.Prime(d.root); err != nil {
			_ = listener.Close()
			for _, l := range additional {
				_ = l.Close()
			}
			return err
		}
		joined := make(chan error, 1)
		providerDone = joined
		go func() { joined <- d.providers.Run(d.root) }()
		defer func() {
			d.cancel()
			if providerDone != nil {
				<-joined
			}
		}()
	}
	done := make(chan error, 1)
	go func() { done <- d.Runtime.Run(listener, additional...) }()
	timer := time.NewTicker(time.Second)
	ticks := 0
	defer timer.Stop()
	for {
		select {
		case err := <-done:
			return err
		case err := <-providerDone:
			providerDone = nil
			d.cancel()
			d.Runtime.Close()
			<-done
			if err == nil {
				err = mounts.ErrUnavailable
			}
			return err
		case <-d.root.Done():
			d.Runtime.Close()
			return <-done
		case <-timer.C:
			ticks++
			if ticks%30 == 0 {
				if calls, spent := d.observerStats.load(); calls > 0 {
					operation, operationSpent := d.operationStats.load()
					fmt.Fprintf(os.Stderr, "owner observer %d calls %s, operation %d calls %s total\n", calls, spent.Round(10*time.Millisecond), operation, operationSpent.Round(10*time.Millisecond))
				}
			}
			if _, err := d.refreshWorkerTrust(d.root); err != nil {
				d.cancel()
				d.Runtime.Close()
				<-done
				return err
			}
			// ADR-196 decision 3: a changed cluster catalog restarts this
			// process, which reads the catalog at start. A failed read is
			// not a change.
			if ticks%15 == 0 && d.clusterCatalogChanged(d.root) {
				d.cancel()
				d.Runtime.Close()
				<-done
				return errClusterCatalogChanged
			}
		}
	}
}

// RunPublic serves the ADR-180 public HTTPS layer until the deployment stops.
// Shutdown waits for in-flight public requests before the deployment releases
// pools and keys; a failed public server stops the whole deployment.
func (d *OwnerDeployment) RunPublic(listener net.Listener) error {
	if d == nil || d.publicHandler == nil || d.root == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	d.mu.Lock()
	if d.closed || d.root.Err() != nil {
		d.mu.Unlock()
		return mounts.ErrUnavailable
	}
	d.owners.Add(1)
	d.mu.Unlock()
	defer d.owners.Done()
	server := &http.Server{Handler: d.publicHandler, TLSConfig: publicTLS(d.publicFiles), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return d.root }}
	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
		_ = server.Close()
	}
	done := make(chan struct{})
	stop := context.AfterFunc(d.root, func() { shutdown(); close(done) })
	err := server.ServeTLS(listener, "", "")
	if stop() {
		d.cancel()
		shutdown()
		return err
	}
	<-done
	return nil
}

// legacyOwnerIdentity is the static-token identity prefix of the legacy full
// owner layout; the installer never produces it (ADR-182).
func legacyOwnerIdentity(startup context.Context, d *OwnerDeployment, in *ownerInputs, governor *postgres.SQLConnectionGovernor) (*ownerIdentityParts, error) {
	pools := map[string]*pgxpool.Pool{}
	users := map[string]bool{}
	roles := []string{"enrollment", "audit", "activation", "registry"}
	for _, role := range roles {
		c, err := in.sqlConfig(startup, "sql-"+role+".json")
		if err != nil || c == nil || users[c.ConnConfig.User] || governor.Govern(c, true) != nil {
			return nil, mounts.ErrUnavailable
		}
		users[c.ConnConfig.User] = true
		pool, err := pgxpool.NewWithConfig(startup, c)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		pools[role] = pool
		d.closers = append(d.closers, pool.Close)
	}
	c := in.config
	configs, err := postgres.NewOwnerConfigurations(startup, pools["registry"], c.InstallationID, c.ClusterID, c.Namespace.UID, c.ConfigurationUID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	current, err := configs.ReadOwnerConfiguration(startup)
	if err != nil || !current.Valid(time.Now()) || current.Configuration.Suspended || current.Configuration.Pool.Namespace != c.Namespace.Name {
		return nil, mounts.ErrUnavailable
	}
	pool := current.Configuration.Pool
	roots, _, err := mtls.OwnerTrustRoots(current.Configuration.IssuerRoots, time.Now())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	ledgers := map[string]*postgres.OwnerEnrollments{}
	for _, role := range []string{"enrollment", "audit", "activation", "registry"} {
		l, err := postgres.NewOwnerEnrollments(startup, pools[role], c.InstallationID, c.ClusterID, c.Namespace.UID, c.ConfigurationUID, ownerRandomID)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		ledgers[role] = l
	}
	control := configuration.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observer, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	guard, err := ownerWorkloadGuard(observer, probe, pool, c.Guard())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	proofs, err := kube.NewOwnerEnrollmentAttester(observer, configs, guard, mountedOwnerPodToken{in})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, pool)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	routes := &app.OwnerRoutes{Configurations: configs, Endpoints: endpoints, Now: time.Now}
	h, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, h.CloseIdleConnections)
	seal, err := kms.NewSealerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-wrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, seal.Close)
	open, err := kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-unwrap.token"), h)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, open.Close)
	storageHTTP, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
	if err != nil {
		return nil, err
	}
	d.closers = append(d.closers, storageHTTP.CloseIdleConnections)
	store, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in.providerInputs}, storageHTTP)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, store.Close)
	audits := &objectstore.OwnerEnrollmentAuditObjects{Store: store, Seal: seal, Open: open}
	parts := &ownerIdentityParts{audit: publicAuditStore{store: store, seal: seal, open: open, keys: h}}
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, pool, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	services := map[string]*app.OwnerEnrollmentCoordinator{}
	for _, usage := range []string{"server", "client"} {
		role := c.KeyService.ServerRole
		if usage == "client" {
			role = c.KeyService.ClientRole
		}
		issuer, err := kms.NewOwnerCertificateIssuerForPoolWithTokenSource(c.KeyService.Endpoint, c.KeyService.PKIMount, role, pool, usage, roots, in.token("owner-"+usage+"-sign.token"), h, time.Now)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		d.closers = append(d.closers, issuer.Close)
		services[usage] = &app.OwnerEnrollmentCoordinator{Verifier: verifier, Proofs: proofs, Ledger: ledgers["enrollment"], Activation: ledgers["activation"], Audit: audits, Acknowledgements: ledgers["audit"], Issuer: issuer, Now: time.Now}
	}
	parts.observer, parts.probe, parts.guard, parts.pools, parts.configs, parts.pool, parts.roots = observer, probe, guard, pools, configs, pool, roots
	parts.ledgers, parts.proofs, parts.endpoints, parts.routes, parts.services = ledgers, proofs, endpoints, routes, services
	return parts, nil
}

// projectionInputs opens one fixed installed projection root (ADR-182). The
// root stays open, and owned by d, until Close.
func (d *OwnerDeployment) projectionInputs(path string) (*providerInputs, error) {
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	in := &providerInputs{files: r, kubernetesEndpoint: d.inputs.kubernetesEndpoint, postgresEndpoint: d.inputs.postgresEndpoint}
	d.closers = append(d.closers, func() { _ = r.Close() }, in.closeHTTP)
	return in, nil
}

// providerAuditCredentials reads the installed audit store credential from
// the provider effects on each use; nothing is cached across reads.
type providerAuditCredentials struct {
	providers *kms.InstalledOwnerProviderEffects
}

func (s providerAuditCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	c, until, err := s.providers.ReadAuditCredentials(ctx)
	if err != nil || !time.Now().Before(until) {
		return aws.Credentials{}, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "installed-owner-provider"}, nil
}

// installedAuditStore is the public layer's audit store in the installed
// layout: provider-held credentials and the provider audit Transit keys.
func (d *OwnerDeployment) installedAuditStore(providers *kms.InstalledOwnerProviderEffects) (publicAuditStore, error) {
	c := d.inputs.config
	if providers == nil || providers.Sealer() == nil || providers.Opener() == nil {
		return publicAuditStore{}, mounts.ErrUnavailable
	}
	h, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
	if err != nil {
		return publicAuditStore{}, err
	}
	d.closers = append(d.closers, h.CloseIdleConnections)
	keys, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
	if err != nil {
		return publicAuditStore{}, err
	}
	d.closers = append(d.closers, keys.CloseIdleConnections)
	store, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, providerAuditCredentials{providers}, h)
	if err != nil {
		return publicAuditStore{}, mounts.ErrUnavailable
	}
	d.closers = append(d.closers, store.Close)
	return publicAuditStore{store: store, seal: providers.Sealer(), open: providers.Opener(), keys: keys}, nil
}

// backendInputs is the backend root: the installed observation projection
// (ADR-182), or the owner root in the legacy layout.
func (d *OwnerDeployment) backendInputs() *providerInputs {
	if d.backend != nil {
		return d.backend
	}
	return d.inputs.providerInputs
}

// errClusterCatalogChanged stops the hub-api so the kubelet restarts it with
// the new catalog (ADR-196); it is a change, never an authority failure.
var errClusterCatalogChanged = fmt.Errorf("cluster catalog changed: %w", cfg.ErrChanged)

func (d *OwnerDeployment) clusterCatalogChanged(ctx context.Context) bool {
	pc := d.publicContext
	if pc == nil || pc.clusters == nil {
		return false
	}
	catalog, err := pc.clusters.ReadClusterCatalog(ctx)
	if err != nil {
		return false
	}
	digest, err := clusterCatalogDigest(catalog)
	return err == nil && digest != pc.clustersDigest
}
