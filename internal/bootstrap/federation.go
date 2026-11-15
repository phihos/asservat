package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	oidcadapter "asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Federation is the ADR-170 hub process for connector-facing duties. It serves
// the ADR-169 lifecycle channel for staged peers with the real SQL duties,
// encrypted audit and connector PKI issuer, and answers ADR-172 owner
// discovery and authentication reads. It holds no browser, MCP, evidence,
// owner-signing or recovery-activation authority.
type Federation struct {
	handler *connectorlifecycle.Handler
	tls     *tls.Config
	port    int
	closers []func()
	// providers are the Kubernetes-auth provider lifetimes (ADR-193), primed
	// before serving and refreshed while serving.
	providers *kms.InstalledFederationProviderEffects
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
	// Setup and the hub write the accepted owner configuration and provider
	// state after this Pod starts: wait in-process for them.
	var f *Federation
	if err = waitStartup(ctx, "federation", startupLog, func(ctx context.Context) (err error) {
		f, err = NewFederation(ctx, files, ids)
		return err
	}, nil); err != nil {
		return err
	}
	defer f.Close()
	serve, stop := context.WithCancel(ctx)
	defer stop()
	if err = f.providers.Prime(ctx); err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	// A stopped provider supervisor stops serving: issuance and audit would
	// otherwise fail later without a visible process stop.
	go func() { _ = f.providers.Run(serve); stop() }()
	listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(f.port)))
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	if err = f.Serve(serve, listener); err == nil && ctx.Err() == nil {
		return mounts.ErrUnavailable // the provider supervisor ended
	}
	return err
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
	return validServiceScope(c.Name, c.Namespace) && c.Port >= 1 && c.Port <= 65535 && c.Concurrency >= 1 && pg && validServiceStore(c.AuditStore) && ownerEndpoint(c.OpenBao) && len(c.Audiences) != 0
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
	roots := map[string][][]byte{}
	for _, name := range []string{contracts.PostgresRootsFile, contracts.ObjectStoreRootsFile, contracts.OpenBaoRootsFile} {
		if roots[name], err = readServiceRoots(startup, files, name); err != nil {
			return f, err
		}
	}
	endpoint, _ := servicePostgres(c.Postgres, roots[contracts.PostgresRootsFile])
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
	mac, accountVersion, err := readAuditMAC(startup, files)
	if err != nil {
		return f, err
	}
	f.closers = append(f.closers, mac.Close)
	storage, err := ownerHTTP(c.AuditStore.Endpoint, roots[contracts.ObjectStoreRootsFile])
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	f.closers = append(f.closers, storage.CloseIdleConnections)
	store, err := objectstore.NewVersionedAudit(c.AuditStore.Endpoint, c.AuditStore.Region, c.AuditStore.Bucket, mountedStorage{in}, storage)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	f.closers = append(f.closers, store.Close)
	recovery, err := postgres.NewRecoveryReader(startup, pools["connector-read"], c.InstallationID)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	owners, err := federationOwnerReads(startup, c, pools["connector-owner-read"])
	if err != nil {
		return f, err
	}
	login := serviceLogin(c.Name, c.Namespace, "federation", contracts.OwnerProviderEndpoint{Endpoint: c.OpenBao, Roots: roots[contracts.OpenBaoRootsFile]}, "audit-wrap", "audit-unwrap", "client-sign", "server-sign")
	names := providerconfig.OpenBaoNamesFor(c.InstallationID)
	keys := kms.FederationProviderKeys{AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: names.FederationAuditKey, PKIMount: contracts.SmallOpenBaoConnectorPKIMount, ClientRole: names.ConnectorClientRole, ServerRole: names.ConnectorServerRole}
	if f.providers, err = kms.NewInstalledFederationProviderEffects(ctx, login, keys, c.Concurrency, files, recoveryProof(recovery)); err != nil {
		return f, &fixedStepError{"providers", mounts.ErrUnavailable}
	}
	providers := f.providers
	f.closers = append(f.closers, func() { _ = providers.CloseAndJoin(context.Background()) })
	profiles, err := postgres.NewConnectorIdentityProfiles(startup, pools["connector-read"])
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	peers := &federationPeers{providers: providers, ids: c.ServiceIDs, pools: pools, mac: mac, accountVersion: accountVersion, recovery: recovery, store: store, seal: providers.Sealer(), open: providers.Opener(), owners: owners, profiles: profiles, offerBacking: federationOfferBacking(c), duties: map[value.ConnectorCluster]federationPeerEntry{}}
	tokens, err := federationTokens(c)
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
	f.handler, err = connectorlifecycle.NewHandler(tokens, federationServices{connectorlifecycle.Runners(peers.resolve), peers, &federationBindings{decoder, remote}}, c.Concurrency)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
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

// federationTokens verifies connector ServiceAccount tokens (ADR-334): the
// hub's own cluster through its API server's issuer discovery, every
// registered workload cluster through its issuer or static JWKS.
func federationTokens(c federationInputs) (connectorTokens, error) {
	var clusters []oidcadapter.ServiceAccountCluster
	split := func(connector string) (string, string, bool) {
		ns, account, ok := strings.Cut(connector, "/")
		return ns, account, ok && ns != "" && account != ""
	}
	if c.LocalConnector != "" {
		config, err := serviceKubernetes()
		if err != nil {
			return connectorTokens{}, &fixedStepError{"tokens/kubernetes", mounts.ErrUnavailable}
		}
		client, err := rest.HTTPClientFor(config)
		ns, account, ok := split(c.LocalConnector)
		if err != nil || !ok {
			return connectorTokens{}, &fixedStepError{"tokens/local", mounts.ErrUnavailable}
		}
		clusters = append(clusters, oidcadapter.ServiceAccountCluster{ClusterID: c.ClusterID, PeerID: c.PeerID, Discovery: config.Host, Namespace: ns, Account: account, Client: client})
	}
	for _, r := range c.Clusters {
		peer, ok := contracts.RemotePeerID(c.InstallationID, r.ClusterID)
		ns, account, valid := split(r.Connector)
		if !ok || !valid || r.ClusterID == c.ClusterID {
			return connectorTokens{}, &fixedStepError{"tokens/cluster", configuration.ErrInvalid}
		}
		clusters = append(clusters, oidcadapter.ServiceAccountCluster{ClusterID: r.ClusterID, PeerID: peer, Issuer: r.Issuer, JWKS: []byte(r.JWKS), Namespace: ns, Account: account})
	}
	v, err := oidcadapter.NewServiceAccountVerifier(c.Audiences, clusters)
	if err != nil {
		return connectorTokens{}, &fixedStepError{"tokens", configuration.ErrInvalid}
	}
	return connectorTokens{v, c.ServiceIDs}, nil
}

type connectorTokens struct {
	verifier *oidcadapter.ServiceAccountVerifier
	ids      contracts.ServiceIDs
}

func (t connectorTokens) VerifyConnector(ctx context.Context, token string) (value.ConnectorCluster, error) {
	c, err := t.verifier.VerifyConnector(ctx, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation connector token refused")
		return value.ConnectorCluster{}, value.ErrDenied
	}
	return value.ConnectorCluster{RootID: t.ids.PermissionRootID, PeerID: c.PeerID, InstallationID: t.ids.InstallationID, ClusterID: c.ClusterID}, nil
}

// federationPeers resolves each presented peer from its staged SQL profile
// (ADR-193) and caches its composed duties while the staged profile and the
// root backing stay unchanged.
// ponytail: one mutex around composition; per-peer locks if peers contend.
type federationPeers struct {
	providers      *kms.InstalledFederationProviderEffects
	ids            contracts.ServiceIDs
	pools          map[string]*pgxpool.Pool
	mac            *auditapp.OperationMAC
	accountVersion string
	recovery       *postgres.RecoveryReader
	store          *objectstore.Store
	seal           *kms.Sealer
	open           *kms.Opener
	owners         connectorlifecycle.OwnerReads
	profiles       *postgres.ConnectorIdentityProfiles
	// offerBacking reads the hub's published regional offer backing; the
	// first bootstrap stages the identity root from it (no root row yet).
	offerBacking func(context.Context) (fleetapp.ConnectorIdentityBacking, error)

	mu     sync.Mutex
	duties map[value.ConnectorCluster]federationPeerEntry
}

type federationPeerEntry struct {
	staged []byte
	duties connectorlifecycle.PeerDuties
}

// federationPeerLimit bounds the cached peers, as the former peer list did.
const federationPeerLimit = 64

func (s *federationPeers) resolve(ctx context.Context, region *connectorlifecycle.Region) (connectorlifecycle.PeerDuties, error) {
	var zero connectorlifecycle.PeerDuties
	p := region.Presented()
	if p.RootID != s.ids.PermissionRootID || p.InstallationID != s.ids.InstallationID {
		return zero, value.ErrDenied
	}
	profile, backing, err := stagedProfile(ctx, s.profiles, p, func(ctx context.Context) error {
		_, err := s.stage(ctx, region, region.Binding())
		return err
	})
	if err != nil {
		return zero, err
	}
	staged, err := json.Marshal(struct {
		Profile value.ConnectorCredentialProfile
		Backing fleetapp.ConnectorIdentityBacking
	}{profile, backing})
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.duties[p]; ok && bytes.Equal(e.staged, staged) {
		return e.duties, nil
	} else if !ok && len(s.duties) >= federationPeerLimit {
		return zero, mounts.ErrUnavailable
	}
	d, err := federationPeer(ctx, s.ids, profile, backing, s.pools, s.mac, s.accountVersion, s.recovery, s.store, s.seal, s.open, s.providers)
	if err != nil {
		return zero, err
	}
	d.Owners, d.Recovery = s.owners, s.recovery
	s.duties[p] = federationPeerEntry{staged: staged, duties: d}
	return d, nil
}

// stagedConnectors reads one peer's staged profile and root backing.
type stagedConnectors interface {
	ReadStagedConnector(context.Context, value.ConnectorCluster) (value.ConnectorCredentialProfile, fleetapp.ConnectorIdentityBacking, error)
}

// stagedProfile stages a registered cluster's source only when it was never
// staged; a suspended or blocked peer stays refused and a failed read
// returns without writing.
func stagedProfile(ctx context.Context, profiles stagedConnectors, p value.ConnectorCluster, stage func(context.Context) error) (value.ConnectorCredentialProfile, fleetapp.ConnectorIdentityBacking, error) {
	profile, backing, err := profiles.ReadStagedConnector(ctx, p)
	if errors.Is(err, value.ErrNotStaged) {
		if err = stage(ctx); err != nil {
			return profile, backing, federationEnrollmentError{"stage", err}
		}
		profile, backing, err = profiles.ReadStagedConnector(ctx, p)
	}
	if err != nil {
		return profile, backing, federationEnrollmentError{"staged-profile", err}
	}
	return profile, backing, nil
}

// federationPeer composes one staged peer's unchanged ADR-153 duties.
func federationPeer(ctx context.Context, c contracts.ServiceIDs, profile value.ConnectorCredentialProfile, backing fleetapp.ConnectorIdentityBacking, pools map[string]*pgxpool.Pool, mac *auditapp.OperationMAC, accountVersion string, recovery *postgres.RecoveryReader, store *objectstore.Store, seal *kms.Sealer, open *kms.Opener, providers *kms.InstalledFederationProviderEffects) (_ connectorlifecycle.PeerDuties, err error) {
	step := "inputs"
	defer func() {
		if err != nil {
			err = federationEnrollmentError{step, err}
		}
	}()
	var zero connectorlifecycle.PeerDuties
	binding := profile.Binding
	q := backing.Policy
	if !profile.Valid() || profile.Suspended || binding.InstallationID != c.InstallationID || profile.RootID != c.PermissionRootID || backing.AccountVersion != accountVersion || q.History == nil {
		return zero, mounts.ErrUnavailable
	}
	step = "process-journal"
	process, err := postgres.NewConnectorProcesses(ctx, pools["connector-journal"], profile.RootID, binding, backing, mac)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "credential-journal"
	credential, err := postgres.NewConnectorCredentials(ctx, pools["connector-journal"], profile.RootID, binding, backing, mac)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "audit-journal"
	journal, err := postgres.NewConnectorAuditJournal(ctx, pools["connector-journal"], q)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "audit-acknowledgements"
	ack, err := postgres.NewConnectorAuditAcknowledgements(ctx, pools["connector-ack"], q)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "audit-objects"
	closed, err := objectstore.NewClosedOperationAuditObjects(store, q.StoreID, seal, open)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "auditor"
	auditor, err := fleetapp.NewConnectorOperationAuditor(q, journal, ack, &objectstore.OperationAuditObjects{Store: store, Seal: seal, Open: open}, closed, ack, time.Now)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "credential-verifier"
	verifier, err := mtls.NewConnectorCredentialVerifier(profile, time.Now)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	step = "credential-issuer"
	var issuers federationIssuer
	for _, usage := range []string{"client", "server"} {
		issuer, err := providers.ConnectorIssuer(usage, profile)
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		if usage == "client" {
			issuers.client = issuer
		} else {
			issuers.server = issuer
		}
	}
	pin := fleetapp.ConnectorQualificationPin{InstallationID: q.InstallationID, StoreID: q.StoreID, BackupProfileID: q.BackupProfileID, Qualification: *q.History}
	step = "source-journal"
	sources, err := postgres.NewConnectorIdentitySources(ctx, pools["connector-source"], profile.RootID, binding, pin)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	reader := pools["connector-read"]
	return connectorlifecycle.PeerDuties{
		Enrollment: fleetapp.ConnectorLifecycleEnrollment{Keys: mtls.EnrollmentProof{}, Recovery: recovery, Journal: process, Audit: auditor, MAC: mac, Now: time.Now},
		Renewal:    fleetapp.ConnectorLifecycleRenewal{Keys: mtls.EnrollmentProof{}, Recovery: recovery, Journal: credential, Audit: auditor, MAC: mac, Issuer: issuers, Verifier: verifier, Now: time.Now},
		Source:     fleetapp.ConnectorIdentityObserver{Journal: sources, Qualification: pin, Binding: binding, Now: time.Now},
		Registry: func(ctx context.Context, source fleetapp.ConnectorIdentitySourceReader) (fleetapp.ConnectorLeafRegistry, error) {
			return postgres.NewConnectorRegistry(ctx, reader, source, profile)
		},
	}, nil
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
	connectorlifecycle.Runners
	peers    *federationPeers
	bindings *federationBindings
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
	if p.RootID != s.peers.ids.PermissionRootID || p.InstallationID != s.peers.ids.InstallationID || p.ClusterID == s.peers.ids.ClusterID {
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

// stage stages the presenting cluster's regional source under the
// hub-decided root backing stored in SQL; without one it is refused.
func (s *federationPeers) stage(ctx context.Context, region *connectorlifecycle.Region, binding value.PeerBinding) (identity.Revision, error) {
	var zero identity.Revision
	backing, found, err := s.profiles.ReadRootBacking(ctx, s.ids.PermissionRootID)
	if err != nil {
		return zero, &fixedStepError{"stage/backing-read", err}
	}
	if !found && s.offerBacking != nil {
		// No identity root yet: the first stage creates it from the backing
		// the hub-api published in its regional offer (the same document
		// every connector observes).
		if backing, err = s.offerBacking(ctx); err != nil {
			return zero, &fixedStepError{"stage/offer-backing", err}
		}
		found = true
	}
	q := backing.Policy
	if !found || !backing.Valid() || q.History == nil || backing.AccountVersion != s.accountVersion || q.RootID != s.ids.PermissionRootID || q.InstallationID != s.ids.InstallationID {
		step := "stage/backing"
		if !found {
			step += "-missing"
		}
		return zero, &fixedStepError{step, mounts.ErrUnavailable}
	}
	pin := fleetapp.ConnectorQualificationPin{InstallationID: q.InstallationID, StoreID: q.StoreID, BackupProfileID: q.BackupProfileID, Qualification: *q.History}
	sources, err := postgres.NewConnectorIdentitySources(ctx, s.pools["connector-source"], s.ids.PermissionRootID, binding, pin)
	if err != nil {
		return zero, &fixedStepError{"stage/sources", mounts.ErrUnavailable}
	}
	c, err := fleetapp.ConnectorIdentityObserver{Reader: region, Journal: sources, Qualification: pin, Binding: binding, Now: time.Now, Backing: &backing}.ObserveConfiguration(ctx)
	if err != nil {
		return zero, &fixedStepError{"stage/observe", err}
	}
	return c.Source.Observation.Profile.Revision, nil
}

func (s federationServices) Enroll(ctx context.Context, region *connectorlifecycle.Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	out, err := s.Runners.Enroll(ctx, region, id, r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation enroll failed: "+federationEnrollmentStep(err)+" "+federationClass(err))
	}
	return out, err
}

func (s federationServices) Issue(ctx context.Context, region *connectorlifecycle.Region, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	out, err := s.Runners.Issue(ctx, region, id, usage, r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation "+usage+" issue failed: "+federationCause(err))
	}
	return out, err
}

// AuthenticateOwner logs the fixed refusal step of a failed owner
// authentication (fleet.WithRefusalSteps); the result is unchanged.
func (s federationServices) AuthenticateOwner(ctx context.Context, region *connectorlifecycle.Region, c value.OwnerCertificate) (connectorlifecycle.OwnerAuthentication, error) {
	var steps []string
	out, err := s.Runners.AuthenticateOwner(fleetapp.WithRefusalSteps(ctx, func(step string) { steps = append(steps, step) }), region, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation owner authentication refused: "+strings.Join(steps, ",")+" "+federationCause(err))
	}
	return out, err
}

func (s federationServices) Registration(ctx context.Context, region *connectorlifecycle.Region, c value.ConnectorCredentialCertificate) (fleetapp.ConnectorLeafRegistration, error) {
	out, err := s.Runners.Registration(ctx, region, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation registration failed: "+federationCause(err))
	}
	return out, err
}

// federationIssuer dispatches the fixed per-usage PKI roles by permit usage.
type federationIssuer struct {
	client, server fleetapp.ConnectorCredentialIssuer
}

func (i federationIssuer) SignConnectorCredential(ctx context.Context, p value.ConnectorCredentialPermit, csr []byte) (value.IssuedConnectorCredential, error) {
	switch p.Usage {
	case "client":
		return i.client.SignConnectorCredential(ctx, p, csr)
	case "server":
		return i.server.SignConnectorCredential(ctx, p, csr)
	}
	return value.IssuedConnectorCredential{}, value.ErrInvalid
}

// Serve runs the channel until ctx ends, then closes the listener and joins.
func (f *Federation) Serve(ctx context.Context, listener net.Listener) error {
	if f == nil || f.handler == nil || ctx == nil || listener == nil {
		return mounts.ErrUnavailable
	}
	mux := http.NewServeMux()
	mux.Handle(connectorlifecycle.Path, f.handler)
	server := &http.Server{Handler: mux, TLSConfig: f.tls, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	select {
	case err := <-done:
		return errors.Join(mounts.ErrUnavailable, err)
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
	defer cancel()
	_ = server.Shutdown(stop) // conversations are bounded at thirty seconds
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

// federationOwnerReads composes the hub-api's unchanged owner registry and
// route reads (ADR-172). The owner configuration and namespace UIDs key the
// SQL rows and are read by name; the owner protection is the platform's
// deterministic workload digest. Nothing here can sign, audit or activate an
// owner.
func federationOwnerReads(ctx context.Context, c federationInputs, pool *pgxpool.Pool) (connectorlifecycle.OwnerReads, error) {
	var zero connectorlifecycle.OwnerReads
	api, err := serviceKubernetes()
	if err != nil {
		return zero, &fixedStepError{"kubernetes", mounts.ErrUnavailable}
	}
	namespaceUID, err := kube.NamespaceUID(ctx, api, c.Namespace)
	if err != nil {
		return zero, &fixedStepError{"kubernetes/namespace", mounts.ErrUnavailable}
	}
	configurationUID, err := kube.ConfigMapUID(ctx, api, c.Namespace, c.Name+"-owner-source")
	if err != nil {
		return zero, &fixedStepError{"kubernetes/owner-configuration", mounts.ErrUnavailable}
	}
	configurations, err := postgres.NewOwnerConfigurations(ctx, pool, c.InstallationID, c.ClusterID, namespaceUID, configurationUID)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	registry, err := postgres.NewOwnerEnrollments(ctx, pool, c.InstallationID, c.ClusterID, namespaceUID, configurationUID, ownerRandomID)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	observer, err := kube.NewPermissionClient(api, c.ClusterID, configuration.NamespaceRef{Name: c.Namespace, UID: namespaceUID}, time.Now)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	// The hub-api accepts its owner configuration; until then the federation
	// restarts rather than serving owner reads without a pool.
	current, err := configurations.ReadOwnerConfiguration(ctx)
	if err != nil || !current.Valid(time.Now()) || current.Configuration.Pool.Namespace != c.Namespace {
		return zero, &fixedStepError{"owner-configuration", mounts.ErrUnavailable}
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, current.Configuration.Pool)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	routes := &fleetapp.OwnerRoutes{Configurations: configurations, Endpoints: endpoints, Now: time.Now}
	return connectorlifecycle.OwnerReads{Candidates: registry, ObservationCandidates: registry, Registry: registry, Authenticator: &fleetapp.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: platformOwnerProtection{time.Now}, Now: time.Now}}, nil
}

// Each stage is a local literal. Do not format SQL/provider errors, request
// bodies, key material or identities into the operator line.
type federationEnrollmentError struct {
	step string
	err  error
}

func (e federationEnrollmentError) Error() string     { return "federation enrollment " + e.step }
func (e federationEnrollmentError) Unwrap() error     { return e.err }
func (e federationEnrollmentError) FixedStep() string { return e.step }
func federationEnrollmentStep(err error) string {
	var failure federationEnrollmentError
	if errors.As(err, &failure) {
		return "resolve/" + failure.step
	}
	return connectorlifecycle.EnrollmentStep(err)
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

// federationOfferBacking reads connectorBacking of `<name>-regional-offer`
// (get on that one name) for the first bootstrap of an installation.
func federationOfferBacking(c federationInputs) func(context.Context) (fleetapp.ConnectorIdentityBacking, error) {
	return func(ctx context.Context) (fleetapp.ConnectorIdentityBacking, error) {
		var zero fleetapp.ConnectorIdentityBacking
		config, err := serviceKubernetes()
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		api, err := kubernetes.NewForConfig(config)
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		call, end := context.WithTimeout(ctx, 5*time.Second)
		defer end()
		object, err := api.CoreV1().ConfigMaps(c.Namespace).Get(call, c.Name+"-regional-offer", meta.GetOptions{})
		if err != nil {
			return zero, mounts.ErrUnavailable
		}
		var offer contracts.RegionalOffer
		if json.Unmarshal([]byte(object.Data[contracts.RegionalOfferFile]), &offer) != nil || offer.InstallationID != c.InstallationID || offer.PermissionRootID != c.PermissionRootID {
			return zero, mounts.ErrUnavailable
		}
		var backing fleetapp.ConnectorIdentityBacking
		d := json.NewDecoder(bytes.NewReader(offer.ConnectorBacking))
		d.DisallowUnknownFields()
		if d.Decode(&backing) != nil || !backing.Valid() {
			return zero, value.ErrInvalid
		}
		return backing, nil
	}
}
