package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
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
	return c, nil
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
	for _, purpose := range []string{"key-configuration", "key-wrap", "key-verify"} {
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
	// ADR-181: verification unwraps for the publisher's verifier role. Download
	// unwrap joins with the native download key authority (ADR-176).
	authority := authapp.KeyOperationAuthorizers{"wrap": wraps, "unwrap/verifier": unwraps}
	if k.handler, err = keyservice.NewHandler([]authapp.KeyService{{Scope: scope, Authority: authority, Backend: backend, Now: time.Now}}, mtls.KeyPeerUnion{KeyClients: keyClients, Connectors: connectors}, time.Now, c.Concurrency); err != nil {
		return k, mounts.ErrUnavailable
	}
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
	select {
	case err := <-done:
		return errors.Join(mounts.ErrUnavailable, err)
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(stop)
	<-done
	return nil
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
