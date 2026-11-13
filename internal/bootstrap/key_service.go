package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/keyservice"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
)

// KeyService is the ADR-176 local key service process for the artifact
// purpose. It holds the protected root key, serves wrap under attempt-scoped
// authority, and never serves an operation without its exact authority.
type KeyService struct {
	handler *keyservice.Handler
	tls     *tls.Config
	port    int
	// catalog is the cluster catalog as read at start, only with downloads;
	// a changed digest restarts the process (ADR-204, as the publisher does
	// under ADR-203 decision 6).
	catalog publicCatalog
	closers []func()
}

// keyServiceInputs are the Helm-rendered configuration plus the generated
// installation IDs; the recovery epoch is the issuer epoch.
type keyServiceInputs struct {
	contracts.KeyServiceConfig
	contracts.ServiceIDs
}

// RunKeyService serves until ctx ends from the fixed mounted inputs.
func RunKeyService(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.KeyServiceDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	ids, err := os.OpenRoot(contracts.IDsRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer ids.Close()
	k, err := NewKeyService(ctx, files, ids)
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

func readKeyServiceInputs(ctx context.Context, files, ids *os.Root) (keyServiceInputs, error) {
	c, err := readServiceConfig(ctx, files, contracts.DecodeKeyServiceConfig)
	if err != nil {
		return keyServiceInputs{}, err
	}
	v, err := readServiceIDs(ctx, ids)
	if err != nil {
		return keyServiceInputs{}, err
	}
	_, pg := servicePostgres(c.Postgres, nil)
	if !validServiceScope(c.Name, c.Namespace) || !artifactScope(v.InstallationID).Valid() || c.Port < 1 || c.Port > 65535 || c.Concurrency < 1 || c.Concurrency > 64 || !pg || !ownerEndpoint(c.OpenBao) {
		return keyServiceInputs{}, &fixedStepError{"config", mounts.ErrUnavailable}
	}
	if d := c.Downloads; d != nil {
		if _, err = serviceTopologyPins(d.RetentionTopologies, nil); err != nil {
			return keyServiceInputs{}, &fixedStepError{"config", err}
		}
	}
	return keyServiceInputs{c, v}, nil
}

// artifactScope is the artifact key scope; its key ID is the one the secrets
// Job writes into `<name>-artifact-key` (artifactKeyID).
func artifactScope(installation string) authorization.KeyScope {
	return authorization.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: artifactKeyID(installation)}
}

// serviceTopologyPins unions the configured topologies with each joined
// catalog slot's topology, as the hub-api does (ADR-196 decision 7). A
// cluster or topology named twice is refused; both sets may be empty.
func serviceTopologyPins(configured []contracts.ServiceTopology, catalog []contracts.OwnerPublicCluster) ([]kube.RetentionTopologyPin, error) {
	pins := make([]kube.RetentionTopologyPin, 0, len(configured)+len(catalog))
	for _, t := range configured {
		pins = append(pins, kube.RetentionTopologyPin{TargetClusterID: t.TargetClusterID, Name: t.Name})
	}
	for _, v := range catalog {
		if v.Topology.TargetClusterID != v.ClusterID {
			return nil, mounts.ErrUnavailable
		}
		pins = append(pins, kube.RetentionTopologyPin{TargetClusterID: v.ClusterID, Name: v.Topology.Name})
	}
	if len(pins) > 1024 {
		return nil, mounts.ErrUnavailable
	}
	clusters, names := map[string]bool{}, map[string]bool{}
	for _, p := range pins {
		if !authorization.UUID(p.TargetClusterID) || len(validation.IsDNS1123Subdomain(p.Name)) != 0 || clusters[p.TargetClusterID] || names[p.Name] {
			return nil, mounts.ErrUnavailable
		}
		clusters[p.TargetClusterID], names[p.Name] = true, true
	}
	return pins, nil
}

// readServiceCatalog reads the cluster catalog once at process start; its
// joined slots add topology pins and a changed digest restarts the process.
func readServiceCatalog(ctx context.Context, observer *kube.PermissionClient, api *rest.Config, namespace, name string) (publicCatalog, error) {
	var out publicCatalog
	uid, err := kube.ConfigMapUID(ctx, api, namespace, name)
	if err != nil {
		return out, &fixedStepError{"catalog", mounts.ErrUnavailable}
	}
	if out.source, err = kube.NewNamedClusterCatalogSource(observer, name, uid); err != nil {
		return out, mounts.ErrUnavailable
	}
	if out.catalog, err = out.source.ReadClusterCatalog(ctx); err != nil {
		return out, &fixedStepError{"catalog", mounts.ErrUnavailable}
	}
	if out.digest, err = clusterCatalogDigest(out.catalog); err != nil {
		return out, mounts.ErrUnavailable
	}
	return out, nil
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
// key-acquisition login, the worker configuration's profile and the retention
// and recovery transaction guards it needs. Topology pins come from the
// configuration and the cluster catalog.
func keyServiceAcquisition(ctx context.Context, c keyServiceInputs, api *rest.Config, observer *kube.PermissionClient, pool *pgxpool.Pool, scope authorization.KeyScope) (*postgres.NativeKeyAuthority, publicCatalog, error) {
	var none publicCatalog
	d := c.Downloads
	if d == nil || pool == nil {
		return nil, none, mounts.ErrUnavailable
	}
	profile, err := kube.ReadWorkerProfile(ctx, observer, c.Name+"-worker-profile", c.InstallationID)
	// The workers' namespace is never the key service's (ADR-204 decision 1).
	if err != nil || profile.Namespace == c.Namespace {
		return nil, none, &fixedStepError{"key-service/worker-configuration", mounts.ErrUnavailable}
	}
	catalog, err := readServiceCatalog(ctx, observer, api, c.Namespace, c.Name+"-cluster-catalog")
	if err != nil {
		return nil, none, &fixedStepError{"key-service/catalog", err}
	}
	pins, err := serviceTopologyPins(d.RetentionTopologies, catalog.catalog.Clusters)
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

func NewKeyService(ctx context.Context, files, ids *os.Root) (k *KeyService, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || ids == nil || disableWorkerCoreDumps() != nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readKeyServiceInputs(ctx, files, ids)
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
	pgRoots, err := readServiceRoots(startup, files, contracts.PostgresRootsFile)
	if err != nil {
		return k, err
	}
	baoRoots, err := readServiceRoots(startup, files, contracts.OpenBaoRootsFile)
	if err != nil {
		return k, err
	}
	endpoint, _ := servicePostgres(c.Postgres, pgRoots)
	in := &providerInputs{files: files, postgresEndpoint: endpoint}
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
			return k, &fixedStepError{"sql/" + purpose, mounts.ErrUnavailable}
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
	scope := artifactScope(c.InstallationID)
	api, err := serviceKubernetes()
	if err != nil {
		return k, &fixedStepError{"kubernetes", mounts.ErrUnavailable}
	}
	namespaceUID, err := kube.NamespaceUID(startup, api, c.Namespace)
	if err != nil {
		return k, &fixedStepError{"kubernetes/namespace", mounts.ErrUnavailable}
	}
	// The root key is the mounted <name>-artifact-key Secret, mounted only
	// into this Pod; SQL keeps the version fingerprints append-only.
	source := &mountedKeySource{files: files, scope: scope, cluster: c.ClusterID, namespace: namespaceUID, epoch: c.IssuerEpoch, now: time.Now}
	ledger, err := postgres.NewLocalKeyConfigurations(startup, pools["key-configuration"], scope, c.ClusterID, namespaceUID, mountedKeySourceID)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	backend, err := kms.LoadProtectedLocalOperations(startup, scope, source, ledger, time.Now)
	if err != nil {
		return k, &fixedStepError{"artifact-key", mounts.ErrUnavailable}
	}
	wraps, err := postgres.NewContextKeyWraps(startup, pools["key-wrap"], c.PermissionRootID, c.IssuerEpoch, scope)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	// ADR-198: connector peers resolve from their staged SQL profiles.
	profiles, err := postgres.NewConnectorIdentityProfiles(startup, pools["key-wrap"])
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	// Client CAs are the worker and connector PKI issuers (field class J).
	keyClientRoots, err := readPKIRoots(startup, c.OpenBao, baoRoots, contracts.SmallOpenBaoWorkerPKIMount)
	if err != nil {
		return k, err
	}
	connectorClientRoots, err := readPKIRoots(startup, c.OpenBao, baoRoots, contracts.SmallOpenBaoConnectorPKIMount)
	if err != nil {
		return k, err
	}
	keyRoots, _, err := mtls.OwnerTrustRoots(keyClientRoots, time.Now())
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
	unwraps, err := postgres.NewContextKeyUnwraps(startup, pools["key-verify"], c.PermissionRootID, c.IssuerEpoch, scope)
	if err != nil {
		return k, mounts.ErrUnavailable
	}
	// ADR-181: verification unwraps for the publisher's verifier role.
	// ADR-204: acquisition unwraps through the native download key authority,
	// only with a Downloads section.
	var acquisition *postgres.NativeKeyAuthority
	if c.Downloads != nil {
		observer, err := kube.NewPermissionClient(api, c.ClusterID, cfg.NamespaceRef{Name: c.Namespace, UID: namespaceUID}, time.Now)
		if err != nil {
			return k, mounts.ErrUnavailable
		}
		if acquisition, k.catalog, err = keyServiceAcquisition(startup, c, api, observer, pools["key-acquisition"], scope); err != nil {
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
	for _, der := range connectorClientRoots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return k, mounts.ErrUnavailable
		}
		clients.AddCert(cert)
	}
	pair, err := readServingPair(startup, files)
	if err != nil {
		return k, err
	}
	k.tls = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients}
	return k, nil
}

// mountedKeySourceID names the mounted key source in the SQL key ledger and
// as its Secret identity: the mount carries no Kubernetes UID.
const mountedKeySourceID = "artifact-key"

// mountedKeySource reads the artifact root key from the mounted
// <name>-artifact-key Secret. The revision generation is the highest key
// version, so an additive rotation advances it; SQL still refuses a changed
// fingerprint for an existing version.
type mountedKeySource struct {
	files                     *os.Root
	scope                     authorization.KeyScope
	cluster, namespace, epoch string
	now                       func() time.Time
}

func (s *mountedKeySource) ReadKeyMaterial(ctx context.Context) (authapp.KeyMaterial, error) {
	var zero authapp.KeyMaterial
	if s == nil || ctx == nil {
		return zero, authapp.ErrKeyUnavailable
	}
	started := s.now()
	payload, err := mounts.Read(ctx, s.files, contracts.ArtifactKeyFile, 16<<10)
	if err != nil || len(payload) == 0 {
		clear(payload)
		return zero, authapp.ErrKeyUnavailable
	}
	var versions struct {
		Keys []struct {
			Version int `json:"version"`
		} `json:"keys"`
	}
	generation := 0
	if json.Unmarshal(payload, &versions) == nil {
		for _, v := range versions.Keys {
			generation = max(generation, v.Version)
		}
	}
	if generation < 1 || generation > 2147483647 {
		clear(payload)
		return zero, authapp.ErrKeyUnavailable
	}
	digest := artifact.Digest(sha256.Sum256(payload))
	c := authorization.LocalKeyConfiguration{Scope: s.scope, ClusterID: s.cluster, NamespaceUID: s.namespace, RecoveryEpoch: s.epoch,
		Revision: identity.Revision{UID: mountedKeySourceID, Generation: int64(generation), Digest: digest}, SecretUID: mountedKeySourceID, SecretDigest: digest,
		ObservedAt: started, FreshUntil: started.Add(5 * time.Second)}
	return authapp.KeyMaterial{Configuration: c, Payload: payload}, nil
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
