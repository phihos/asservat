package bootstrap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Federation is the ADR-170 hub process for connector-facing duties. It
// authenticates the owner certificates observed by connectors, delivers work
// hints and stores their AccessBindings. It
// holds no browser, MCP, evidence, signing, audit or recovery-activation
// authority.
type Federation struct {
	handler  *connectorlifecycle.Handler
	tunnel   *connectorlifecycle.TunnelHandler
	work     *connectorlifecycle.WorkHandler
	workPool *pgxpool.Pool
	tls      *tls.Config
	port     int
	closers  []func()
}

// federationInputs are the Helm-rendered configuration plus the generated
// installation IDs; the federation's own values never come from a request.
type federationInputs struct {
	contracts.FederationConfig
	contracts.ServiceIDs
}

// RunFederation serves until ctx ends from the fixed mounted inputs.
func RunFederation(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.FederationDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	ids, err := os.OpenRoot(contracts.IDsRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer ids.Close()
	// The hub writes the accepted owner configuration after this Pod starts:
	// wait in-process for it.
	var f *Federation
	if err = waitStartup(ctx, "federation", startupLog, func(ctx context.Context) (err error) {
		f, err = NewFederation(ctx, files, ids)
		return err
	}, nil); err != nil {
		return err
	}
	defer f.Close()
	listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(f.port)))
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	return f.Serve(ctx, listener)
}

func readFederationInputs(ctx context.Context, files, ids *os.Root) (federationInputs, error) {
	c, err := readServiceConfig(ctx, files, contracts.DecodeFederationConfig)
	if err != nil {
		return federationInputs{}, err
	}
	if !validFederationConfig(c) {
		return federationInputs{}, &fixedStepError{"config", configuration.ErrInvalid}
	}
	v, err := readServiceIDs(ctx, ids)
	if err != nil {
		return federationInputs{}, err
	}
	return federationInputs{c, v}, nil
}

func validFederationConfig(c contracts.FederationConfig) bool {
	_, pg := servicePostgres(c.Postgres, nil)
	return validServiceScope(c.Name, c.Namespace) && c.Port >= 1 && c.Port <= 65535 && c.Concurrency >= 1 && pg && len(c.ConnectorTokens.Audiences) != 0
}

func NewFederation(ctx context.Context, files, ids *os.Root) (f *Federation, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil || ids == nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readFederationInputs(ctx, files, ids)
	if err != nil {
		return nil, err
	}
	f = &Federation{port: c.Port}
	defer func() {
		if err != nil {
			f.Close()
			f = nil
		}
	}()
	startup, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	postgresRoots, err := readServiceRoots(startup, files, contracts.PostgresRootsFile)
	if err != nil {
		return f, err
	}
	endpoint, _ := servicePostgres(c.Postgres, postgresRoots)
	in := &providerInputs{files: files, postgresEndpoint: endpoint}
	pools := map[string]*pgxpool.Pool{}
	users := map[string]bool{}
	for _, purpose := range contracts.PublicRuntimeFederationPurposes() {
		config, err := in.sqlConfig(startup, "sql-"+purpose+".json")
		if err != nil || users[config.ConnConfig.User] {
			return f, &fixedStepError{"sql/" + purpose, mounts.ErrUnavailable}
		}
		users[config.ConnConfig.User] = true
		config.ConnConfig.RuntimeParams["application_name"] = "asservat-federation"
		pool, err := pgxpool.NewWithConfig(startup, config)
		if err != nil {
			return f, mounts.ErrUnavailable
		}
		pools[purpose] = pool
		f.closers = append(f.closers, pool.Close)
	}
	owners, err := federationOwnerAuthenticator(startup, c, pools["connector-owner-read"])
	if err != nil {
		return f, err
	}
	tokens, err := newConnectorTokens(c.ConnectorTokens, c.ServiceIDs, "federation")
	if err != nil {
		return f, err
	}
	decoder, err := kube.NewAccessBindingSpecDecoder()
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	remote, err := postgres.NewRemoteAccessBindings(startup, pools["connector-delivery"], c.PermissionRootID)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	settings, err := newFederationSettings(c)
	if err != nil {
		return f, err
	}
	active := make([]string, 0, len(settings.names)+1)
	for cluster := range settings.names {
		active = append(active, cluster)
	}
	if c.ConnectorTokens.LocalConnector != "" {
		active = append(active, c.ClusterID)
	}
	if err = remote.WithdrawUnregistered(startup, active); err != nil {
		return f, &fixedStepError{"sql/withdraw-remote-bindings", err}
	}
	f.handler, err = connectorlifecycle.NewHandler(tokens, federationServices{owners, c.ServiceIDs, &federationBindings{decoder, remote}, settings}, c.Concurrency)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	f.workPool = pools["connector-owner-read"]
	f.work = &connectorlifecycle.WorkHandler{Tokens: tokens, Concurrency: c.Concurrency, Ready: func(ctx context.Context, cluster string) error {
		return postgres.NotifyConnectorReady(ctx, f.workPool, cluster)
	}}
	f.tunnel = &connectorlifecycle.TunnelHandler{Tokens: tokens, Owners: settings.ownerEndpoints, Allowed: settings.allowed, Dial: (&net.Dialer{}).DialContext}
	// The serving identity is deployment-provided server authentication only;
	// connectors authenticate with their ServiceAccount tokens.
	pair, err := readServingPair(startup, files)
	if err != nil {
		return f, err
	}
	f.tls = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{pair}}
	return f, nil
}

// readServingPair reads the mounted serving certificate: a cert-manager,
// existing or chart-generated kubernetes.io/tls Secret.
func readServingPair(ctx context.Context, files *os.Root) (tls.Certificate, error) {
	certificate, err := mounts.Read(ctx, files, "tls.crt", 64<<10)
	if err != nil {
		return tls.Certificate{}, &fixedStepError{"tls", mounts.ErrUnavailable}
	}
	key, err := mounts.Read(ctx, files, "tls.key", 16<<10)
	if err != nil {
		return tls.Certificate{}, &fixedStepError{"tls", mounts.ErrUnavailable}
	}
	pair, err := tls.X509KeyPair(certificate, key)
	clear(key)
	if err != nil {
		return tls.Certificate{}, &fixedStepError{"tls", mounts.ErrUnavailable}
	}
	return pair, nil
}

// Operator diagnostics: one fixed line per refused presentation or failed
// conversation, with a closed cause. Never inputs, identities or remote text.
func federationCause(err error) string {
	var step interface{ FixedStep() string }
	if errors.As(err, &step) {
		return step.FixedStep() + "/" + federationClass(err)
	}
	return federationClass(err)
}

func federationClass(err error) string {
	switch {
	case errors.Is(err, value.ErrDenied):
		return "denied"
	case errors.Is(err, value.ErrInvalid):
		return "invalid"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled"
	case errors.Is(err, connectorlifecycle.ErrChannel):
		return "channel"
	}
	return "unavailable"
}

type federationServices struct {
	owners   *fleetapp.OwnerAuthenticator
	ids      contracts.ServiceIDs
	bindings *federationBindings
	*federationSettings
}

// federationBindings records connectors' AccessBinding deliveries (ADR-329)
// with the shared observed-binding validator.
type federationBindings struct {
	decoder *kube.AccessBindingSpecDecoder
	store   interface {
		StoreRemoteBindings(context.Context, configuration.RemoteBindings, string) error
		RemoteBindingsDigest(context.Context, string) (string, error)
	}
}

// AccessBindings stores the presenting connector's delivery under its
// authenticated cluster, observed no later than the presentation (ADR-329).
// The payload names no cluster; a binding the schema refuses grants nothing.
func (s federationServices) AccessBindings(ctx context.Context, region *connectorlifecycle.Region) error {
	if s.bindings == nil || region == nil {
		return mounts.ErrUnavailable
	}
	p := region.Presented()
	if p.RootID != s.ids.PermissionRootID || p.InstallationID != s.ids.InstallationID || p.ClusterID == s.ids.ClusterID {
		return mounts.ErrUnavailable
	}
	// The connector answers "unchanged" when its current LIST has the
	// stored digest; the stored delivery then stays in effect.
	stored, err := s.bindings.store.RemoteBindingsDigest(ctx, p.ClusterID)
	if err != nil {
		return err
	}
	delivery, unchanged, err := region.ReadAccessBindings(ctx, stored)
	if err != nil || unchanged {
		return err
	}
	bindings, err := s.bindings.decoder.DeliveredBindings(p.ClusterID, delivery)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation access bindings refused: invalid delivery")
		return err
	}
	d := configuration.RemoteBindings{ClusterID: p.ClusterID, ObservedAt: region.VerifiedAt(), Bindings: bindings}
	if !d.Valid() {
		fmt.Fprintln(os.Stderr, "federation access bindings refused: over the per-cluster bounds")
		return configuration.ErrLimit
	}
	if err = s.bindings.store.StoreRemoteBindings(ctx, d, delivery.Digest()); err != nil {
		fmt.Fprintln(os.Stderr, "federation access bindings store failed: "+federationCause(err))
	}
	return err
}

// AuthenticateOwner logs the fixed refusal step of a failed owner
// authentication (fleet.WithRefusalSteps); the result is unchanged.
func (s federationServices) AuthenticateOwner(ctx context.Context, c value.OwnerCertificate) (connectorlifecycle.OwnerAuthentication, error) {
	var steps []string
	out, err := connectorlifecycle.AuthenticateOwner(fleetapp.WithRefusalSteps(ctx, func(step string) { steps = append(steps, step) }), s.owners, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation owner authentication refused: "+strings.Join(steps, ",")+" "+federationCause(err))
	}
	return out, err
}

// Serve runs the channel until ctx ends, then closes the listener and joins.
func (f *Federation) Serve(ctx context.Context, listener net.Listener) error {
	if f == nil || f.handler == nil || ctx == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	mux := http.NewServeMux()
	if f.work != nil {
		postgres.ListenPayloads(ctx, f.workPool, postgres.ConnectorWorkChannel, f.work.Publish)
		mux.Handle(connectorlifecycle.WorkPath, f.work)
	}
	mux.Handle(connectorlifecycle.Path, f.handler)
	mux.Handle(connectorlifecycle.TunnelPath, f.tunnel)
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, Handler: mux, TLSConfig: f.tls, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-done:
		return errors.Join(mounts.ErrUnavailable, err)
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
	defer cancel()
	// A peer blocked on an HTTP/2 flow-control window may still hold an
	// active write after its request context ends. Close it at shutdown's bound.
	if err := server.Shutdown(stop); err != nil {
		_ = server.Close()
	}
	<-done
	return nil
}

func (f *Federation) Close() {
	if f == nil {
		return
	}
	for i := len(f.closers) - 1; i >= 0; i-- {
		f.closers[i]()
	}
	f.closers = nil
}

// federationOwnerAuthenticator composes the hub-api's unchanged owner registry and
// route reads (ADR-172). The owner configuration and namespace UIDs key the
// SQL rows and are read by name; the owner protection is the platform's
// deterministic workload digest. Nothing here can sign, audit or activate an
// owner.
func federationOwnerAuthenticator(ctx context.Context, c federationInputs, pool *pgxpool.Pool) (*fleetapp.OwnerAuthenticator, error) {
	api, err := serviceKubernetes()
	if err != nil {
		return nil, &fixedStepError{"kubernetes", mounts.ErrUnavailable}
	}
	namespaceUID, err := kube.NamespaceUID(ctx, api, c.Namespace)
	if err != nil {
		return nil, &fixedStepError{"kubernetes/namespace", mounts.ErrUnavailable}
	}
	configurationUID, err := kube.ConfigMapUID(ctx, api, c.Namespace, c.Name+"-owner-source")
	if err != nil {
		return nil, &fixedStepError{"kubernetes/owner-configuration", mounts.ErrUnavailable}
	}
	configurations, err := postgres.NewOwnerConfigurations(ctx, pool, c.InstallationID, c.ClusterID, namespaceUID, configurationUID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	registry, err := postgres.NewOwnerEnrollments(ctx, pool, c.InstallationID, c.ClusterID, namespaceUID, configurationUID, ownerRandomID)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	observer, err := kube.NewPermissionClient(api, c.ClusterID, configuration.NamespaceRef{Name: c.Namespace, UID: namespaceUID}, time.Now)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	// The hub-api accepts its owner configuration; until then the federation
	// restarts rather than serving owner reads without a pool.
	current, err := configurations.ReadOwnerConfiguration(ctx)
	if err != nil || !current.Valid(time.Now()) || current.Configuration.Pool.Namespace != c.Namespace {
		return nil, &fixedStepError{"owner-configuration", mounts.ErrUnavailable}
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, current.Configuration.Pool)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	routes := &fleetapp.OwnerRoutes{Configurations: configurations, Endpoints: endpoints, Now: time.Now}
	return &fleetapp.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: platformOwnerProtection{time.Now}, Now: time.Now}, nil
}

// platformOwnerProtection replaces the removed owner workload guard proof:
// the hub namespace is protected by Kubernetes RBAC, so the protection digest
// is the deterministic digest of the owner Deployment's cluster, namespace and
// name (field map coupling 2). It performs no I/O and confers no authority.
type platformOwnerProtection struct{ now func() time.Time }

func (p platformOwnerProtection) ReadOwnerProtection(ctx context.Context, pool value.OwnerPool) (value.OwnerProtection, error) {
	if ctx == nil || ctx.Err() != nil || !pool.Valid() {
		return value.OwnerProtection{}, value.ErrUnavailable
	}
	start := p.now()
	return value.OwnerProtection{Pool: pool, Digest: artifact.Digest(contracts.WorkloadSourceDigest(pool.ClusterID, pool.Namespace, pool.Deployment)), ObservedAt: start, FreshUntil: identity.Check(start, identity.SQLFenced).Until()}, nil
}
