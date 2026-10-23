package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/keyservice"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KeyService is the ADR-176 local key service process for the artifact
// purpose. It holds the protected root key, serves wrap under attempt-scoped
// authority, and never serves an operation without its exact authority.
type KeyService struct {
	handler *keyservice.Handler
	tls     *tls.Config
	port    int
	// catalog is the guarded cluster catalog as read at start, only with
	// downloads; a changed digest restarts the process (ADR-204, as the
	// publisher does under ADR-203 decision 6).
	catalog publicCatalog
	closers []func()
}

// RunKeyService serves until ctx ends from the fixed installation projection.
func RunKeyService(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.KeyServiceDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	k, err := NewKeyService(ctx, files)
	if err != nil {
		return err
	}
	defer k.Close()
	listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(k.port)))
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	return k.Serve(ctx, listener)
}

func readKeyServiceDeployment(ctx context.Context, files *os.Root) (contracts.KeyServiceDeployment, error) {
	b, err := mounts.Read(ctx, files, "key-service.json", contracts.KeyServiceDeploymentMaxBytes)
	if err != nil {
		return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeKeyServiceDeployment(bytes.NewReader(b))
	p := c.Postgres
	scope := authorization.KeyScope{InstallationID: c.InstallationID, Purpose: "artifact", KeyID: c.KeyID}
	if err != nil || c.Format != contracts.KeyServiceDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.ClusterID) || !authorization.UUID(c.PermissionRootID) || !authorization.UUID(c.RecoveryEpoch) || !scope.Valid() || c.Port < 1 || c.Port > 65535 || c.Concurrency < 1 || c.Concurrency > 64 || !authorization.UUID(c.Namespace.UID) || !identity.Text(c.Namespace.Name, 63) || !identity.Text(c.KeySource.Name, 253) || !authorization.UUID(c.KeySource.UID) || !ownerEndpoint(c.Kubernetes.Endpoint) {
		return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
	}
	if _, err = netip.ParseAddr(p.Host); err != nil && !ownerDNSName.MatchString(p.Host) || !identity.Text(p.Database, 63) || p.Port < 1 || p.Port > 65535 || p.MaxConnections != 1 {
		return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
	}
	if _, _, err = mtls.OwnerTrustRoots(c.KeyClientRoots, time.Now()); err != nil {
		return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
	}
	if _, _, err = mtls.OwnerTrustRoots(c.ConnectorClientRoots, time.Now()); err != nil {
		return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
	}
	if d := c.Downloads; d != nil {
		if _, err = keyServiceWorkerProfile(c); err != nil || !capacityRuntimeReference(d.ClusterCatalog.Source) || !capacityRuntimeGuard(d.ClusterCatalog.Guard) || d.RetentionTopologies == nil {
			return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
		}
		if _, err = keyServiceTopologyPins(c, nil); err != nil {
			return contracts.KeyServiceDeployment{}, mounts.ErrUnavailable
		}
	}
	return c, nil
}

// keyServiceWorkerProfile derives the profile of the pinned worker document
// with the guarded source reader's own parse. The pin only selects the
// profile: the native key authority spends a slot only while SQL's current
// audited revision equals it (ADR-070), so a stale pin denies. The workers'
// namespace is never the key service's (ADR-204 decision 1).
func keyServiceWorkerProfile(c contracts.KeyServiceDeployment) (authorization.DownloadWorkerProfile, error) {
	d := c.Downloads
	if d == nil || !capacityRuntimeReference(d.WorkerSource) {
		return authorization.DownloadWorkerProfile{}, mounts.ErrUnavailable
	}
	w, err := kube.PinnedWorkerConfiguration(d.WorkerProfile, d.WorkerSource.UID, c.InstallationID, c.ClusterID)
	if err != nil || w.Profile.NamespaceUID == c.Namespace.UID || w.Profile.Namespace == c.Namespace.Name {
		return authorization.DownloadWorkerProfile{}, mounts.ErrUnavailable
	}
	return w.Profile, nil
}

// keyServiceTopologyPins unions the fixed pins with each joined catalog
// slot's pin as the hub-api and the publisher do (ADR-196 decision 7): a
// slot's pin must name its own cluster and fixed slot topology, and a cluster
// or topology named twice is refused. Both sets may be empty.
func keyServiceTopologyPins(c contracts.KeyServiceDeployment, catalog []contracts.OwnerPublicCluster) ([]kube.RetentionTopologyPin, error) {
	if c.Downloads == nil {
		return nil, mounts.ErrUnavailable
	}
	all := slices.Clone(c.Downloads.RetentionTopologies)
	for i, v := range catalog {
		t := v.Topology
		if t.TargetClusterID != v.ClusterID || t.Name != contracts.OwnerClusterSourceName(c.InstallationID, i+1, "topology") {
			return nil, mounts.ErrUnavailable
		}
		all = append(all, t)
	}
	if len(all) > 1024 {
		return nil, mounts.ErrUnavailable
	}
	pins := make([]kube.RetentionTopologyPin, len(all))
	clusters, names := map[string]bool{}, map[string]bool{}
	for i, p := range all {
		b, err := hex.DecodeString(p.SHA256)
		if !validOwnerNativeTopology(p) || err != nil || clusters[p.TargetClusterID] || names[p.Name] {
			return nil, mounts.ErrUnavailable
		}
		clusters[p.TargetClusterID], names[p.Name] = true, true
		pins[i] = kube.RetentionTopologyPin{TargetClusterID: p.TargetClusterID, Name: p.Name, UID: p.UID}
		copy(pins[i].ContentDigest[:], b)
	}
	return pins, nil
}

// keyServiceAuthorities is the artifact scope's authority map: wraps,
// verifier unwraps and, only with downloads, acquisition unwraps through the
// native download key authority (ADR-204 decision 8). A role without an
// entry is denied; there is no bare "unwrap" entry to fall back to.
func keyServiceAuthorities(wraps, verifier authapp.KeyOperationAuthorizer, acquisition *postgres.NativeKeyAuthority) authapp.KeyOperationAuthorizers {
	out := authapp.KeyOperationAuthorizers{"wrap": wraps, "unwrap/verifier": verifier}
	if acquisition != nil {
		out["unwrap/acquisition"] = acquisition
	}
	return out
}

// keyServiceAcquisition composes the native download key authority from the
// key-acquisition login, the pinned worker profile and the retention and
// recovery transaction guards it needs. Topology pins come from the guarded
// cluster catalog, proved with the probe account like the hub-api's reads.
func keyServiceAcquisition(ctx context.Context, c contracts.KeyServiceDeployment, in *providerInputs, observer *kube.PermissionClient, pool *pgxpool.Pool, scope authorization.KeyScope) (*postgres.NativeKeyAuthority, publicCatalog, error) {
	var none publicCatalog
	profile, err := keyServiceWorkerProfile(c)
	if err != nil || pool == nil {
		return nil, none, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, time.Now)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	catalog, err := readPublicClusterCatalog(ctx, contracts.OwnerDeployment{Namespace: c.Namespace, Public: &contracts.OwnerPublicDeployment{ClusterCatalog: c.Downloads.ClusterCatalog}}, observer, probe)
	if err != nil {
		return nil, none, &fixedStepError{"key-service/catalog", err}
	}
	pins, err := keyServiceTopologyPins(c, catalog.catalog.Clusters)
	if err != nil {
		return nil, none, &fixedStepError{"key-service/topology", err}
	}
	topologies, err := kube.NewRetentionTopologies(observer, c.PermissionRootID, pins)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	retention, err := postgres.NewRetentionTransactionGuard(c.PermissionRootID, topologies)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	recovery, err := postgres.NewRecoveryTransactionGuard(c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	native, err := postgres.NewNativeKeyAuthority(ctx, pool, c.PermissionRootID, profile, scope, postgres.DownloadTransactionGuards{Retention: retention, Recovery: recovery})
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	plans, err := postgres.NewSharedContextQueryPlans(ctx, pool, c.PermissionRootID, c.InstallationID, profile)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	queries, err := postgres.NewContextQueries(ctx, pool, c.PermissionRootID, postgres.EffectTransactionGuards{Retention: retention, Recovery: recovery}, plans, nil)
	if err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	if _, err = postgres.AttachProjectionWorkers(queries, profile); err != nil {
		return nil, none, mounts.ErrUnavailable
	}
	projection, err := postgres.NewProjectionKeys(queries, scope)
	if err != nil || native.WithProjectionKeys(projection) != nil {
		return nil, none, mounts.ErrUnavailable
	}
	return native, catalog, nil
}

func NewKeyService(ctx context.Context, files *os.Root) (k *KeyService, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readKeyServiceDeployment(ctx, files)
	if err != nil {
		return nil, err
	}
	k = &KeyService{port: c.Port}
	defer func() {
		if err != nil {
			k.Close()
			k = nil
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	in := &providerInputs{files: files, postgresEndpoint: c.Postgres, kubernetesEndpoint: c.Kubernetes}
	k.closers = append(k.closers, in.closeHTTP)
	pools := map[string]*pgxpool.Pool{}
	users := map[string]bool{}
	purposes := []string{"key-configuration", "key-wrap", "key-verify"}
	if c.Downloads != nil {
		// ADR-204: the acquisition login exists only with downloads.
		purposes = append(purposes, "key-acquisition")
	}
	for _, purpose := range purposes {
		config, err := in.sqlConfig(startup, "sql-"+purpose+".json")
		if err != nil || users[config.ConnConfig.User] {
			return k, mounts.ErrUnavailable
		}
		users[config.ConnConfig.User] = true
		config.ConnConfig.RuntimeParams["application_name"] = "asservat-key-service"
		pool, err := pgxpool.NewWithConfig(startup, config)
		if err != nil {
			return k, mounts.ErrUnavailable
		}
		pools[purpose] = pool
		k.closers = append(k.closers, pool.Close)
	}
	scope := authorization.KeyScope{InstallationID: c.InstallationID, Purpose: "artifact", KeyID: c.KeyID}
	control := cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}
	observer, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	source, err := kube.NewLocalKeySource(observer, c.KeySource.Name, c.KeySource.UID, scope)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	ledger, err := postgres.NewLocalKeyConfigurations(startup, pools["key-configuration"], scope, c.ClusterID, c.Namespace.UID, c.KeySource.UID)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	backend, err := kms.LoadProtectedLocalOperations(startup, scope, source, ledger, time.Now)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	wraps, err := postgres.NewContextKeyWraps(startup, pools["key-wrap"], c.PermissionRootID, c.RecoveryEpoch, scope)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	// ADR-198: connector peers resolve from their staged SQL profiles.
	profiles, err := postgres.NewConnectorIdentityProfiles(startup, pools["key-wrap"])
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	keyRoots, _, err := mtls.OwnerTrustRoots(c.KeyClientRoots, time.Now())
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	keyClients, err := mtls.NewKeyPeerVerifier(keyRoots, c.InstallationID, time.Now)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	connectors, err := mtls.NewConnectorKeyPeerVerifier(c.InstallationID, c.PermissionRootID, profiles.ReadConnectorProfile, time.Now)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	unwraps, err := postgres.NewContextKeyUnwraps(startup, pools["key-verify"], c.PermissionRootID, c.RecoveryEpoch, scope)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	// ADR-181: verification unwraps for the publisher's verifier role.
	// ADR-204: acquisition unwraps through the native download key authority,
	// only with a Downloads section.
	var acquisition *postgres.NativeKeyAuthority
	if c.Downloads != nil {
		if acquisition, k.catalog, err = keyServiceAcquisition(startup, c, in, observer, pools["key-acquisition"], scope); err != nil {
			return k, err
		}
	}
	authority := keyServiceAuthorities(wraps, unwraps, acquisition)
	if k.handler, err = keyservice.NewHandler([]authapp.KeyService{{Scope: scope, Authority: authority, Backend: backend, Now: time.Now}}, mtls.KeyPeerUnion{KeyClients: keyClients, Connectors: connectors}, time.Now, c.Concurrency); err != nil {
		return k, mounts.ErrUnavailable
	}
	k.handler.Report = eventLog(os.Stderr, "key service refused")
	// The TLS layer accepts key-client and connector client chains; the
	// handler's peer union then selects exactly one verifier per leaf.
	clients := keyRoots.Clone()
	for _, der := range c.ConnectorClientRoots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return k, mounts.ErrUnavailable
		}
		clients.AddCert(cert)
	}
	certificate, err := mounts.Read(startup, files, "tls.crt", 64<<10)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	key, err := mounts.Read(startup, files, "tls.key", 16<<10)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	pair, err := tls.X509KeyPair(certificate, key)
	clear(key)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	k.tls = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}
	return k, nil
}

// Serve accepts only TLS 1.3 with a verified client certificate; the handler
// rechecks the exact peer and authority for every operation.
func (k *KeyService) Serve(ctx context.Context, listener net.Listener) error {
	if k == nil || k.handler == nil || ctx == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	mux := http.NewServeMux()
	mux.Handle(contracts.KeyServicePath, k.handler)
	server := &http.Server{Handler: mux, TLSConfig: k.tls, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	// With downloads, a changed cluster catalog restarts the process, which
	// reads the joined slots' topology pins only at start.
	var changed <-chan time.Time
	if k.catalog.source != nil {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		changed = ticker.C
	}
	var result error
	for stopped := false; !stopped; {
		select {
		case err := <-done:
			return errors.Join(mounts.ErrUnavailable, err)
		case <-ctx.Done():
			stopped = true
		case <-changed:
			// A failed read is not a change.
			if k.clusterCatalogChanged(ctx) {
				stopped, result = true, errClusterCatalogChanged
			}
		}
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(stop)
	<-done
	return result
}

func (k *KeyService) clusterCatalogChanged(ctx context.Context) bool {
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	catalog, err := k.catalog.source.ReadClusterCatalog(call)
	if err != nil {
		return false
	}
	digest, err := clusterCatalogDigest(catalog)
	return err == nil && digest != k.catalog.digest
}

func (k *KeyService) Close() {
	if k == nil {
		return
	}
	for i := len(k.closers) - 1; i >= 0; i-- {
		k.closers[i]()
	}
	k.closers = nil
}
