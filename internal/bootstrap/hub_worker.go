package bootstrap

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// hubWorker is the Helm-native A-HWORK process. Helm renders its config and
// every Kubernetes object; RBAC protects the sources it reads. It runs the
// configuration child always and the capacity, cleanup and permission
// children when their config sections are present, all under one scheduling
// Lease. Product checks (recovery fence, SQL effect fences, encrypted audit)
// are unchanged.
type hubWorker struct {
	config    contracts.HubWorkerConfig
	ids       contracts.InstallationIDs
	files     *os.Root
	namespace cfg.NamespaceRef
	// fleetUID and ownerUID are the source ConfigMaps' UIDs, read by name.
	fleetUID, ownerUID string
	// inputs reads mounted credentials and builds Kubernetes/SQL clients.
	inputs     *providerInputs
	auditStore contracts.OwnerAuditStore
	keyRoots   [][]byte
	admission  *app.WorkerRuntimeAdmission
	authority  *authorityAuditTurn
	recovery   *postgres.RecoveryReader
	providers  *kms.InstalledConfigurationProviderEffects
	audit      *installedConfigurationAudit
	leader     *kube.ReconciliationLeader
	reconciler *app.ConfigurationReconciler

	root    context.Context
	cancel  context.CancelFunc
	closers []func()
	once    sync.Once
	mu      sync.Mutex
	closed  bool
	running bool
	owners  sync.WaitGroup

	// Shared between children: the capacity child publishes the evidence
	// store ID of its stored qualification for context deletion (ADR-205)
	// and lends its namespace guard readers to the permission reconciler
	// (ADR-247).
	deletionMu      sync.Mutex
	evidenceStoreID string
	guards          sharedNamespaceGuards
}

// RunHubWorker is the `hub-worker` command.
func RunHubWorker(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	files, err := os.OpenRoot(contracts.HubWorkerDeploymentRoot)
	if err != nil {
		return &fixedStepError{"config", mounts.ErrUnavailable}
	}
	defer files.Close()
	ids, err := os.OpenRoot(contracts.InstallationIDsRoot)
	if err != nil {
		return &fixedStepError{"ids", mounts.ErrUnavailable}
	}
	defer ids.Close()
	w, err := newHubWorker(ctx, files, ids)
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Run()
}

// readHubWorkerConfig reads the Helm-rendered config, completes the OpenBao
// names Helm does not render and checks it.
func readHubWorkerConfig(ctx context.Context, files *os.Root, ids contracts.InstallationIDs) (contracts.HubWorkerConfig, error) {
	b, err := mounts.Read(ctx, files, contracts.HubWorkerConfigFile, contracts.HubWorkerConfigMaxBytes)
	if err != nil {
		return contracts.HubWorkerConfig{}, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeHubWorkerConfig(bytes.NewReader(b))
	if err != nil {
		return contracts.HubWorkerConfig{}, mounts.ErrUnavailable
	}
	completeHubWorkerConfig(&c, ids)
	if validateHubWorkerConfig(c) != nil {
		return contracts.HubWorkerConfig{}, mounts.ErrUnavailable
	}
	return c, nil
}

// completeHubWorkerConfig sets the OpenBao names that Helm does not render:
// the configuration auth mount and token audience, the audit mount and key,
// and the installation's worker configuration audit and context deletion
// signing keys, exactly as `asservat setup` creates them.
func completeHubWorkerConfig(c *contracts.HubWorkerConfig, ids contracts.InstallationIDs) {
	n := providerconfig.OpenBaoNamesFor(ids.InstallationID)
	audit := contracts.SmallOpenBaoAuditMount
	c.Provider.AuthMount = contracts.SmallOpenBaoConfigurationAuthMount
	c.Provider.Audience = contracts.ConfigurationProviderAudience(ids.InstallationID, ids.ClusterID)
	c.KeyService.AuditMount, c.KeyService.AuditKey = audit, n.AuditKey
	if c.Permission != nil && c.Permission.WorkerConfiguration != nil {
		c.Provider.WorkerConfigurationAudit = contracts.OwnerPublicTransit{Mount: audit, Key: n.WorkerConfigurationAuditKey}
	}
	if c.Cleanup != nil || c.Permission != nil && c.Permission.ContextDeletion != nil {
		c.Provider.ContextDeletionSigning = contracts.OwnerPublicTransit{Mount: audit, Key: n.DeletionSigningKey}
	}
}

func validateHubWorkerConfig(c contracts.HubWorkerConfig) error {
	if len(validation.IsDNS1123Label(c.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(c.ServiceAccount)) != 0 {
		return mounts.ErrUnavailable
	}
	for _, name := range []string{c.FleetSource, c.OwnerSource, c.LeaderLease} {
		if len(validation.IsDNS1123Subdomain(name)) != 0 {
			return mounts.ErrUnavailable
		}
	}
	if c.FleetSource == c.OwnerSource || c.Postgres.Port < 1 || c.Postgres.Port > 65535 || c.Postgres.Database == "" || c.Postgres.Host == "" ||
		!ownerEndpoint(c.AuditStore.Endpoint) || c.AuditStore.Bucket == "" || c.AuditStore.Region == "" || !ownerEndpoint(c.KeyService.Endpoint) ||
		!ownerProviderName.MatchString(c.KeyService.AuditMount) || !ownerProviderName.MatchString(c.KeyService.AuditKey) ||
		!ownerProviderName.MatchString(c.Provider.AuthMount) || c.Provider.Audience == "" ||
		!ownerProviderName.MatchString(c.Provider.Roles.AuditWrap) || !ownerProviderName.MatchString(c.Provider.Roles.AuditUnwrap) {
		return mounts.ErrUnavailable
	}
	return nil
}

// readPEMRoots reads a mounted PEM bundle as DER certificates.
func readPEMRoots(ctx context.Context, files *os.Root, name string) ([][]byte, error) {
	b, err := mounts.Read(ctx, files, name, 64<<10)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	var out [][]byte
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
	if len(out) == 0 || len(out) > 8 {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

// inClusterKubernetes is the in-cluster API endpoint with the projected
// kube-root-ca.crt roots.
func inClusterKubernetes(ctx context.Context, files *os.Root) (contracts.OwnerProviderEndpoint, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return contracts.OwnerProviderEndpoint{}, mounts.ErrUnavailable
	}
	roots, err := readPEMRoots(ctx, files, contracts.HubWorkerKubernetesRootsFile)
	if err != nil {
		return contracts.OwnerProviderEndpoint{}, err
	}
	return contracts.OwnerProviderEndpoint{Endpoint: "https://" + net.JoinHostPort(host, port), Roots: roots}, nil
}

func newHubWorker(ctx context.Context, files, idFiles *os.Root) (_ *hubWorker, err error) {
	at := "start"
	defer func() {
		if err != nil {
			err = &fixedStepError{at, err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || files == nil || idFiles == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	root, cancel := context.WithCancel(ctx)
	w := &hubWorker{files: files, root: root, cancel: cancel}
	complete := false
	defer func() {
		if !complete {
			w.Close()
		}
	}()
	startup, end := context.WithTimeout(root, 30*time.Second)
	defer end()
	at = "ids"
	if w.ids, err = contracts.ReadInstallationIDs(idFiles); err != nil {
		return nil, mounts.ErrUnavailable
	}
	at = "config"
	if w.config, err = readHubWorkerConfig(startup, files, w.ids); err != nil {
		return nil, err
	}
	at = "roots"
	kubernetes, err := inClusterKubernetes(startup, files)
	if err != nil {
		return nil, err
	}
	pgRoots, err := readPEMRoots(startup, files, contracts.HubWorkerPostgresRootsFile)
	if err != nil {
		return nil, err
	}
	auditRoots, err := readPEMRoots(startup, files, contracts.HubWorkerAuditStoreRootsFile)
	if err != nil {
		return nil, err
	}
	if w.keyRoots, err = readPEMRoots(startup, files, contracts.HubWorkerKeyServiceRootsFile); err != nil {
		return nil, err
	}
	c := w.config
	w.auditStore = contracts.OwnerAuditStore{Endpoint: c.AuditStore.Endpoint, Roots: auditRoots, Region: c.AuditStore.Region, Bucket: c.AuditStore.Bucket}
	w.inputs = &providerInputs{files: files, kubernetesEndpoint: kubernetes,
		postgresEndpoint: contracts.OwnerPostgresEndpoint{Host: c.Postgres.Host, Port: c.Postgres.Port, Database: c.Postgres.Database, Roots: pgRoots, MaxConnections: 1}}
	w.closers = append(w.closers, w.inputs.closeHTTP)

	at = "namespace"
	nsUID, err := kube.ReadNamespaceUID(startup, w.inputs.kubernetes(contracts.HubWorkerKubernetesTokenFile), c.Namespace)
	if err != nil {
		return nil, err
	}
	w.namespace = cfg.NamespaceRef{Name: c.Namespace, UID: nsUID}
	observer, err := w.kubeClient()
	if err != nil {
		return nil, err
	}
	at = "sources"
	if w.fleetUID, err = observer.ConfigMapUID(startup, c.FleetSource); err != nil {
		return nil, err
	}
	if w.ownerUID, err = observer.ConfigMapUID(startup, c.OwnerSource); err != nil {
		return nil, err
	}

	at = "sql"
	var pools [3]*pgxpool.Pool
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		name, known := postgres.ConfigurationRuntimeRoleName(w.ids.InstallationID, purpose)
		if !known {
			return nil, mounts.ErrUnavailable
		}
		if pools[i], err = w.pool(startup, "sql-"+purpose+".json", name, "asservat-hub-worker"); err != nil {
			return nil, err
		}
		w.closers = append(w.closers, pools[i].Close)
	}
	at = "admission"
	if w.admission, err = app.NewWorkerRuntimeAdmission(root); err != nil {
		return nil, err
	}
	w.closers = append(w.closers, w.admission.Close)
	w.authority = newAuthorityAuditTurn(w.admission)
	at = "recovery"
	if w.recovery, err = postgres.NewRecoveryReader(startup, pools[0], w.ids.InstallationID); err != nil {
		return nil, err
	}
	at = "stores"
	fleetStore, err := postgres.NewFleetObservation(startup, pools[0], w.ids.InstallationID)
	if err != nil {
		return nil, err
	}
	ownerStore, err := postgres.NewOwnerConfigurations(startup, pools[1], w.ids.InstallationID, w.ids.ClusterID, nsUID, w.ownerUID)
	if err != nil {
		return nil, err
	}
	ack, err := postgres.NewCurrentOwnerConfigurationAcknowledgements(startup, pools[2], w.ids.InstallationID, w.ids.ClusterID, nsUID, w.ownerUID)
	if err != nil {
		return nil, err
	}
	at = "provider"
	p := c.Provider
	w.providers, err = kms.NewInstalledConfigurationProviderEffects(root, kms.ConfigurationProviderInput{
		InstallationID: w.ids.InstallationID, ClusterID: w.ids.ClusterID, NamespaceUID: nsUID, OwnerSourceUID: w.ownerUID,
		Namespace: c.Namespace, ServiceAccount: c.ServiceAccount, Endpoint: c.KeyService.Endpoint, Roots: w.keyRoots, AuthMount: p.AuthMount,
		AuditMount: c.KeyService.AuditMount, AuditKey: c.KeyService.AuditKey, Roles: p.Roles,
		WorkerConfigurationAudit: p.WorkerConfigurationAudit, ContextDeletionSigning: p.ContextDeletionSigning,
		TokenFile: contracts.HubWorkerProviderTokenFile, AuditCredentialFile: contracts.HubWorkerAuditStorageFile,
	}, files, w.recovery, w.admission)
	if err != nil {
		return nil, err
	}
	if w.audit, err = newInstalledConfigurationAudit(w.auditScope(), w.providers); err != nil {
		return nil, err
	}
	w.closers = append(w.closers, w.audit.Close)
	at = "sources"
	fleetSource, err := kube.NewFleetSettingsClient(observer, c.FleetSource, w.fleetUID, w.ids.InstallationID, w.ids.IssuerEpoch)
	if err != nil {
		return nil, err
	}
	// The owner issuer roots are the owner PKI CA (unauthenticated read).
	ownerRoots := func(ctx context.Context) ([][]byte, error) {
		return kms.ReadPKIRoots(ctx, c.KeyService.Endpoint, w.keyRoots, contracts.SmallOpenBaoOwnerPKIMount)
	}
	ownerSource, err := kube.NewOwnerSourceReader(observer, c.OwnerSource, w.ownerUID, w.ids.InstallationID, w.ids.IssuerEpoch, ownerRoots)
	if err != nil {
		return nil, err
	}
	w.reconciler = &app.ConfigurationReconciler{
		Fleet: &app.TrustObserver{Settings: fleetSource, Projection: &configurationRuntimeFleetProjection{actual: fleetStore, admission: w.admission}, Now: time.Now},
		Owner: &app.OwnerConfigurationObserver{Reader: ownerSource, Ledger: ownerStore, Audit: w.audit, Acknowledgements: ack, Now: time.Now},
	}
	at = "leader"
	leaderClient, err := w.kubeClient()
	if err != nil {
		return nil, err
	}
	if w.leader, err = kube.NewReconciliationLeader(leaderClient, c.LeaderLease, ownerRandomID()); err != nil || startup.Err() != nil {
		return nil, mounts.ErrUnavailable
	}
	complete = true
	return w, nil
}

func (w *hubWorker) auditScope() hubWorkerAuditScope {
	return hubWorkerAuditScope{store: w.auditStore, installationID: w.ids.InstallationID, clusterID: w.ids.ClusterID, namespaceUID: w.namespace.UID, ownerSourceUID: w.ownerUID}
}

// kubeClient returns a new client of the worker's own account in its
// namespace, with its own request limiter.
func (w *hubWorker) kubeClient() (*kube.PermissionClient, error) {
	return w.kubeClientFor(w.inputs.kubernetes(contracts.HubWorkerKubernetesTokenFile))
}

// kubeOpeningClient is kubeClient with the ADR-208 opening limiter.
func (w *hubWorker) kubeOpeningClient() (*kube.PermissionClient, error) {
	return w.kubeClientFor(kube.WithOpeningBurst(w.inputs.kubernetes(contracts.HubWorkerKubernetesTokenFile)))
}

func (w *hubWorker) kubeClientFor(config *rest.Config) (*kube.PermissionClient, error) {
	c, err := kube.NewPermissionClient(config, w.ids.ClusterID, w.namespace, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return c, nil
}

// pool opens one single-connection pool from the mounted `file` credential
// of the `<name>-sql-hub-worker` Secret and checks that it connects as the
// expected derived role. The caller closes it.
func (w *hubWorker) pool(ctx context.Context, file, role, application string) (*pgxpool.Pool, error) {
	if ctx == nil || ctx.Err() != nil || role == "" {
		return nil, mounts.ErrUnavailable
	}
	config, err := w.inputs.sqlConfig(ctx, file)
	if err != nil || config.ConnConfig.User != role {
		return nil, &fixedStepError{"sql/" + file, mounts.ErrUnavailable}
	}
	config.MaxConns, config.MinConns = 1, 0
	config.ConnConfig.RequireAuth = "scram-sha-256"
	config.ConnConfig.RuntimeParams["application_name"] = application
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, &fixedStepError{"sql/" + file, mounts.ErrUnavailable}
	}
	if err = postgres.VerifySessionRole(ctx, pool, role); err != nil {
		pool.Close()
		return nil, &fixedStepError{"sql/" + file, err}
	}
	return pool, nil
}

// hubWorkerChild is one Lease-owned child.
type hubWorkerChild struct {
	name string
	run  func(context.Context) error
}

func (w *hubWorker) children() []hubWorkerChild {
	out := []hubWorkerChild{{"configuration", w.runConfiguration}}
	if w.config.Capacity != nil {
		out = append(out, hubWorkerChild{"capacity", w.runCapacity})
	}
	if w.config.Cleanup != nil {
		out = append(out, hubWorkerChild{"cleanup", w.runCleanup})
	}
	if w.config.Permission != nil {
		out = append(out, hubWorkerChild{"permission", w.runPermission})
	}
	return out
}

func (w *hubWorker) Run() error {
	if w == nil || w.leader == nil || w.reconciler == nil {
		return mounts.ErrUnavailable
	}
	w.mu.Lock()
	if w.closed || w.running || w.root == nil || w.root.Err() != nil {
		w.mu.Unlock()
		return mounts.ErrUnavailable
	}
	w.running = true
	w.owners.Add(1)
	w.mu.Unlock()
	// Release this owner before Close can wait for it.
	defer func() { w.owners.Done(); w.Close() }()
	children := w.children()
	return w.leader.Run(w.root, func(lease context.Context) error {
		return runHubWorkerChildren(lease, children)
	})
}

// Every child receives the same Lease cancellation. The first return closes
// all; this callback cannot report joined until all children have returned.
func runHubWorkerChildren(ctx context.Context, children []hubWorkerChild) error {
	if ctx == nil || ctx.Err() != nil || len(children) == 0 {
		return mounts.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, len(children))
	for _, c := range children {
		if c.run == nil {
			cancel()
			return mounts.ErrUnavailable
		}
	}
	for _, c := range children {
		go func() { done <- hubWorkerChildStop(c.name, c.run(call)) }()
	}
	err := <-done
	cancel()
	for range len(children) - 1 {
		<-done
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return mounts.ErrUnavailable
	}
	return err
}

// runConfiguration runs the fleet/owner reconciler beside the provider
// credential loop. Missing provider/recovery authority does not prevent the
// fleet observer from maintaining its own accepted source.
func (w *hubWorker) runConfiguration(ctx context.Context) error {
	if w == nil || w.reconciler == nil || w.providers == nil || w.admission == nil || ctx == nil || ctx.Err() != nil {
		return mounts.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- w.reconciler.RunWithIndependentOwnerAudit(call, w.admission) }()
	go func() { done <- w.providers.Run(call) }()
	err := <-done
	cancel()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return mounts.ErrUnavailable
	}
	return err
}

func (w *hubWorker) Close() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		w.mu.Lock()
		w.closed = true
		if w.cancel != nil {
			w.cancel()
		}
		w.mu.Unlock()
		w.owners.Wait()
		if w.providers != nil {
			// The provider close interval is used once. A bounded failure still
			// joins cancelled work locally before dependencies are released.
			_ = w.providers.CloseAndJoin(context.Background())
		}
		for i := len(w.closers) - 1; i >= 0; i-- {
			w.closers[i]()
		}
	})
}

// EvidenceStoreID returns the evidence store ID of the capacity child's
// stored qualification, or false before the capacity child has read it.
func (w *hubWorker) EvidenceStoreID() (string, bool) {
	if w == nil {
		return "", false
	}
	w.deletionMu.Lock()
	defer w.deletionMu.Unlock()
	if w.evidenceStoreID == "" || w.root == nil || w.root.Err() != nil {
		return "", false
	}
	return w.evidenceStoreID, true
}

// publishEvidenceStoreID records the evidence store ID once; a different
// later value is refused (the stored qualification never changes it).
func (w *hubWorker) publishEvidenceStoreID(store string) error {
	if w == nil || !authorization.UUID(store) {
		return mounts.ErrUnavailable
	}
	w.deletionMu.Lock()
	defer w.deletionMu.Unlock()
	if w.evidenceStoreID != "" && w.evidenceStoreID != store {
		return mounts.ErrUnavailable
	}
	w.evidenceStoreID = store
	return nil
}

func cloneContextDeletion(v contracts.ContextDeletionDeployment) contracts.ContextDeletionDeployment {
	roots := make([][]byte, len(v.EvidenceStore.Roots))
	for i, root := range v.EvidenceStore.Roots {
		roots[i] = bytes.Clone(root)
	}
	v.EvidenceStore.Roots = roots
	keys := make(map[string][]byte, len(v.Signing.PublicKeys))
	for id, key := range v.Signing.PublicKeys {
		keys[id] = bytes.Clone(key)
	}
	v.Signing.PublicKeys = keys
	return v
}

// hubWorkerChildStop names the child that returned first, so the process's
// stop message carries a fixed child and stage name and the error class.
func hubWorkerChildStop(child string, err error) error {
	if err == nil {
		// Children run until cancelled; an early nil return is a stop too.
		return &fixedStepError{child + "/returned", mounts.ErrUnavailable}
	}
	return &fixedStepError{child, err}
}

// HubWorkerDiagnostic is the hub-worker's stop message: fixed child and stage
// names and the error class only, never provider, SQL or Kubernetes text.
func HubWorkerDiagnostic(err error) string {
	step := "startup"
	var inner interface{ FixedStep() string }
	if errors.As(err, &inner) {
		step = inner.FixedStep()
	}
	return "service stopped at " + step + " (" + errorClass(err) + "): configuration, credentials or original deadline unavailable"
}
