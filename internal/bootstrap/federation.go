package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/clustercredential"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Federation is the ADR-170 hub process for connector-facing duties. It serves
// the ADR-169 lifecycle channel for installer-pinned peers with the real SQL
// duties, encrypted audit and connector PKI issuer. It holds no browser, MCP,
// evidence, owner-signing or recovery-activation authority; with the optional
// owner input it answers ADR-172 owner discovery and authentication reads.
type Federation struct {
	handler  *connectorlifecycle.Handler
	rotation *clustercredential.Handler
	tls      *tls.Config
	port     int
	closers  []func()
	// providers is set with ProviderAuthentication (ADR-193): Kubernetes-auth
	// provider lifetimes, primed before serving and refreshed while serving.
	providers *kms.InstalledFederationProviderEffects
}

// RunFederation serves until ctx ends. All inputs come from the fixed
// installation-owned projection; no flag or request can replace them.
func RunFederation(ctx context.Context) error {
	files, err := os.OpenRoot(contracts.FederationDeploymentRoot)
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	defer files.Close()
	f, err := NewFederation(ctx, files)
	if err != nil {
		return err
	}
	defer f.Close()
	serve, stop := context.WithCancel(ctx)
	defer stop()
	if f.providers != nil {
		if err = f.providers.Prime(ctx); err != nil {
			return errors.Join(mounts.ErrUnavailable, err)
		}
		// A stopped provider supervisor stops serving: issuance and audit
		// would otherwise fail later without a visible process stop.
		go func() { _ = f.providers.Run(serve); stop() }()
	}
	listener, err := (&net.ListenConfig{KeepAlive: -1}).Listen(ctx, "tcp", net.JoinHostPort("", strconv.Itoa(f.port)))
	if err != nil {
		return errors.Join(mounts.ErrUnavailable, err)
	}
	if err = f.Serve(serve, listener); err == nil && ctx.Err() == nil {
		return mounts.ErrUnavailable // the provider supervisor ended
	}
	return err
}

func readFederationDeployment(ctx context.Context, files *os.Root) (contracts.FederationDeployment, error) {
	b, err := mounts.Read(ctx, files, "federation.json", contracts.FederationDeploymentMaxBytes)
	if err != nil {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeFederationDeployment(bytes.NewReader(b))
	k, p := c.KeyService, c.Postgres
	if err != nil || c.Format != contracts.FederationDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.ClusterID) || !authorization.UUID(c.PermissionRootID) || c.Port < 1 || c.Port > 65535 || c.Concurrency < 1 || c.Concurrency > 16 {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	if !ownerProviderName.MatchString(k.AuditMount) || !ownerProviderName.MatchString(k.AuditKey) || !ownerProviderName.MatchString(k.PKIMount) || !ownerProviderName.MatchString(k.ClientRole) || !ownerProviderName.MatchString(k.ServerRole) || k.ClientRole == k.ServerRole || k.AuditMount == k.PKIMount || !identity.Text(c.AuditStore.Region, 128) || !identity.Text(c.AuditStore.Bucket, 63) || !ownerEndpoint(k.Endpoint) || !ownerEndpoint(c.AuditStore.Endpoint) {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	// One MaxConns=1 pool per federation role (ADR-170 connection limit three).
	if _, err = netip.ParseAddr(p.Host); err != nil && !ownerDNSName.MatchString(p.Host) || !identity.Text(p.Database, 63) || p.Port < 1 || p.Port > 65535 || p.MaxConnections != 1 {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	if c.Owner != nil && !validOwnerGuard(*c.Owner) {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	// Kubernetes-auth credentials refresh only under the hub workload guard's
	// current proof, so they need the owner guard inputs.
	if a := c.ProviderAuthentication; a != nil && (c.Owner == nil || a.Namespace != c.Owner.Namespace || providerconfig.ValidateFederationProviderAuthentication(c, *a, time.Now()) != nil) {
		return contracts.FederationDeployment{}, mounts.ErrUnavailable
	}
	return c, nil
}

func NewFederation(ctx context.Context, files *os.Root) (f *Federation, err error) {
	if ctx == nil || ctx.Err() != nil || files == nil {
		return nil, mounts.ErrUnavailable
	}
	c, err := readFederationDeployment(ctx, files)
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
	in := &providerInputs{files: files, postgresEndpoint: c.Postgres}
	if c.Owner != nil {
		in.kubernetesEndpoint = c.Owner.Kubernetes
	}
	pools := map[string]*pgxpool.Pool{}
	users := map[string]bool{}
	for _, purpose := range contracts.PublicRuntimeFederationPurposes() {
		if purpose == "connector-owner-read" && c.Owner == nil {
			continue // the ADR-172 owner purposes stay refused
		}
		config, err := in.sqlConfig(startup, "sql-federation-"+purpose+".json")
		if err != nil || users[config.ConnConfig.User] {
			return f, mounts.ErrUnavailable
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
	mac, accountVersion, err := readFederationMAC(startup, files, c)
	if err != nil {
		return f, err
	}
	f.closers = append(f.closers, mac.Close)
	keys, err := ownerHTTP(c.KeyService.Endpoint, c.KeyService.Roots)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	f.closers = append(f.closers, keys.CloseIdleConnections)
	var seal *kms.Sealer
	var open *kms.Opener
	if c.ProviderAuthentication == nil {
		// Legacy static token files; the installed layout uses the provider
		// lifetimes composed after the owner guard below.
		if seal, err = kms.NewSealerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-wrap.token"), keys); err != nil {
			return f, mounts.ErrUnavailable
		}
		f.closers = append(f.closers, seal.Close)
		if open, err = kms.NewOpenerWithTokenSource(c.KeyService.Endpoint, c.KeyService.AuditMount, c.KeyService.AuditKey, in.token("audit-unwrap.token"), keys); err != nil {
			return f, mounts.ErrUnavailable
		}
		f.closers = append(f.closers, open.Close)
	}
	storage, err := ownerHTTP(c.AuditStore.Endpoint, c.AuditStore.Roots)
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
	var owners connectorlifecycle.OwnerReads
	var guard *kube.OwnerWorkloadProtection
	if c.Owner != nil {
		if owners, guard, err = federationOwnerReads(startup, c, pools["connector-owner-read"], in); err != nil {
			return f, err
		}
	}
	if c.ProviderAuthentication != nil {
		if guard == nil {
			return f, mounts.ErrUnavailable
		}
		// Every provider login and renewal needs the hub workload guard's
		// current proof and a current recovery observation (ADR-193).
		proof := func(ctx context.Context) (time.Time, error) {
			_, until, err := guard.Current(ctx)
			if err != nil {
				return time.Time{}, err
			}
			r, err := recovery.RecoveryState(ctx)
			if err != nil || !r.Valid(time.Now()) {
				return time.Time{}, mounts.ErrUnavailable
			}
			return identity.Earlier(until, r.FreshUntil), nil
		}
		if f.providers, err = kms.NewInstalledFederationProviderEffects(ctx, c, files, proof); err != nil {
			return f, mounts.ErrUnavailable
		}
		providers := f.providers
		f.closers = append(f.closers, func() { _ = providers.CloseAndJoin(context.Background()) })
		seal, open = providers.Sealer(), providers.Opener()
	}
	profiles, err := postgres.NewConnectorIdentityProfiles(startup, pools["connector-read"])
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	peers := &federationPeers{providers: f.providers, c: c, pools: pools, mac: mac, accountVersion: accountVersion, recovery: recovery, store: store, seal: seal, open: open, keys: keys, in: in, owners: owners, profiles: profiles, duties: map[value.ClusterCredentialProfile]federationPeerEntry{}}
	credentials, err := postgres.NewClusterCredentials(startup, pools["cluster-credential"], c.PermissionRootID)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	if c.Connector != nil {
		if err = federationBootstrap(startup, c, pools, store, seal, open, peers); err != nil {
			return f, err
		}
	}
	presenter := federationPresenter{fleetapp.ClusterCredentialVerifier{Store: credentials}}
	if f.rotation, err = clustercredential.NewHandler(presenter, c.Concurrency); err != nil {
		return f, mounts.ErrUnavailable
	}
	f.handler, err = connectorlifecycle.NewHandler(presenter, mtls.EnrollmentProof{}, federationServices{connectorlifecycle.Runners(peers.resolve), peers}, c.Concurrency)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	// The serving identity is deployment-provided server authentication only;
	// every presentation is bound to this TLS session's own exporter.
	certificate, err := mounts.Read(startup, files, "tls.crt", 64<<10)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	key, err := mounts.Read(startup, files, "tls.key", 16<<10)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	pair, err := tls.X509KeyPair(certificate, key)
	clear(key)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	f.tls = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, Certificates: []tls.Certificate{pair}}
	return f, nil
}

// federationBootstrap composes the ADR-193 generation-1 activation: the
// claim on the cluster-credential login, its acknowledgement on the separate
// connector-ack login, both encrypted audit records and the 00064 ledger.
func federationBootstrap(ctx context.Context, c contracts.FederationDeployment, pools map[string]*pgxpool.Pool, store *objectstore.Store, seal *kms.Sealer, open *kms.Opener, peers *federationPeers) error {
	var backing fleetapp.ConnectorIdentityBacking
	d := json.NewDecoder(bytes.NewReader(c.Connector.Backing))
	d.DisallowUnknownFields()
	if d.Decode(&backing) != nil || !backing.Valid() || backing.Policy.RootID != c.PermissionRootID || backing.Policy.InstallationID != c.InstallationID || backing.AccountVersion != peers.accountVersion {
		return mounts.ErrUnavailable
	}
	claims, err := postgres.NewEnrollmentClaims(ctx, pools["cluster-credential"], c.InstallationID)
	if err != nil {
		return mounts.ErrUnavailable
	}
	audits, err := postgres.NewEnrollmentClaimAudits(ctx, pools["connector-ack"], c.InstallationID)
	if err != nil {
		return mounts.ErrUnavailable
	}
	ledger, err := postgres.NewClusterBootstraps(ctx, pools["cluster-credential"], c.InstallationID)
	if err != nil {
		return mounts.ErrUnavailable
	}
	peers.connector = &backing
	peers.bootstrap = &fleetapp.ClusterBootstrapActivation{Claims: claims, ClaimAudits: audits, ClaimObjects: &objectstore.EnrollmentClaimObjects{Store: store, Seal: seal, Open: open},
		Bootstraps: ledger, Audit: &objectstore.ClusterBootstrapAuditObjects{Store: store, Seal: seal, Open: open}, Policy: value.DefaultClusterCredentialPolicy(), Now: time.Now}
	return nil
}

func readFederationMAC(ctx context.Context, files *os.Root, c contracts.FederationDeployment) (*auditapp.OperationMAC, string, error) {
	b, err := mounts.Read(ctx, files, "federation-audit-keys.json", 16<<10)
	if err != nil {
		return nil, "", mounts.ErrUnavailable
	}
	defer clear(b)
	v, err := contracts.DecodeFederationAuditKeys(bytes.NewReader(b))
	defer clear(v.InputKey)
	defer clear(v.AccountKey)
	if err != nil || v.Format != contracts.FederationAuditKeysFormat || v.InstallationID != c.InstallationID || v.RootID != c.PermissionRootID {
		return nil, "", mounts.ErrUnavailable
	}
	mac, err := auditapp.NewOperationMAC(v.InputVersion, v.InputKey, v.AccountVersion, v.AccountKey)
	if err != nil {
		return nil, "", mounts.ErrUnavailable
	}
	return mac, v.AccountVersion, nil
}

// federationPeers resolves each presented peer from its staged SQL profile
// (ADR-193) and caches its composed duties while the staged profile and the
// root backing stay unchanged.
// ponytail: one mutex around composition; per-peer locks if peers contend.
type federationPeers struct {
	providers      *kms.InstalledFederationProviderEffects
	c              contracts.FederationDeployment
	pools          map[string]*pgxpool.Pool
	mac            *auditapp.OperationMAC
	accountVersion string
	recovery       *postgres.RecoveryReader
	store          *objectstore.Store
	seal           *kms.Sealer
	open           *kms.Opener
	keys           *http.Client
	in             *providerInputs
	owners         connectorlifecycle.OwnerReads
	profiles       *postgres.ConnectorIdentityProfiles
	// connector is the deployment's hub-decided initial root backing and
	// bootstrap the generation-1 activation (ADR-193); both are nil without
	// the connector block, which refuses the bootstrap purpose.
	connector *fleetapp.ConnectorIdentityBacking
	bootstrap *fleetapp.ClusterBootstrapActivation

	mu     sync.Mutex
	duties map[value.ClusterCredentialProfile]federationPeerEntry
}

type federationPeerEntry struct {
	staged []byte
	duties connectorlifecycle.PeerDuties
}

// federationPeerLimit bounds the cached peers, as the former peer list did.
const federationPeerLimit = 64

func (s *federationPeers) resolve(ctx context.Context, p value.ClusterCredentialProfile) (connectorlifecycle.PeerDuties, error) {
	var zero connectorlifecycle.PeerDuties
	if p.RootID != s.c.PermissionRootID || p.InstallationID != s.c.InstallationID {
		return zero, value.ErrDenied
	}
	profile, backing, err := s.profiles.ReadStagedConnector(ctx, p)
	if err != nil {
		return zero, value.ErrDenied // never staged, suspended or blocked
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
	d, err := federationPeer(ctx, s.c, profile, backing, s.pools, s.mac, s.accountVersion, s.recovery, s.store, s.seal, s.open, s.keys, s.in, s.providers)
	if err != nil {
		return zero, err
	}
	d.Owners, d.Recovery = s.owners, s.recovery
	s.duties[p] = federationPeerEntry{staged: staged, duties: d}
	return d, nil
}

// federationPeer composes one staged peer's unchanged ADR-153 duties.
func federationPeer(ctx context.Context, c contracts.FederationDeployment, profile value.ConnectorCredentialProfile, backing fleetapp.ConnectorIdentityBacking, pools map[string]*pgxpool.Pool, mac *auditapp.OperationMAC, accountVersion string, recovery *postgres.RecoveryReader, store *objectstore.Store, seal *kms.Sealer, open *kms.Opener, keys *http.Client, in *providerInputs, providers *kms.InstalledFederationProviderEffects) (connectorlifecycle.PeerDuties, error) {
	var zero connectorlifecycle.PeerDuties
	binding := profile.Binding
	q := backing.Policy
	if !profile.Valid() || profile.Suspended || binding.InstallationID != c.InstallationID || profile.RootID != c.PermissionRootID || backing.AccountVersion != accountVersion || q.History == nil {
		return zero, mounts.ErrUnavailable
	}
	process, err := postgres.NewConnectorProcesses(ctx, pools["connector-journal"], profile.RootID, binding, backing, mac)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	credential, err := postgres.NewConnectorCredentials(ctx, pools["connector-journal"], profile.RootID, binding, backing, mac)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	journal, err := postgres.NewConnectorAuditJournal(ctx, pools["connector-journal"], q)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	ack, err := postgres.NewConnectorAuditAcknowledgements(ctx, pools["connector-ack"], q)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	closed, err := objectstore.NewClosedOperationAuditObjects(store, q.StoreID, seal, open)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	auditor, err := fleetapp.NewConnectorOperationAuditor(q, journal, ack, &objectstore.OperationAuditObjects{Store: store, Seal: seal, Open: open}, closed, ack, time.Now)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	verifier, err := mtls.NewConnectorCredentialVerifier(profile, time.Now)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	var issuers federationIssuer
	for _, usage := range []string{"client", "server"} {
		role := c.KeyService.ClientRole
		if usage == "server" {
			role = c.KeyService.ServerRole
		}
		var issuer *kms.ConnectorCredentialIssuer
		var err error
		if providers != nil {
			issuer, err = providers.ConnectorIssuer(usage, profile)
		} else {
			issuer, err = kms.NewConnectorCredentialIssuerWithTokenSource(c.KeyService.Endpoint, in.token("connector-"+usage+"-sign.token"), c.KeyService.PKIMount, role, usage, profile, keys, time.Now)
		}
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
	switch {
	case errors.Is(err, value.ErrClusterCredentialFenced):
		return "cluster-credential-fenced"
	case errors.Is(err, value.ErrClusterCredentialDenied):
		return "cluster-credential-denied"
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

type federationPresenter struct {
	fleetapp.ClusterCredentialVerifier
}

func (p federationPresenter) Present(ctx context.Context, r value.ClusterCredentialRequest, signature, exporter []byte) (value.ClusterCredentialPresentation, error) {
	out, err := p.ClusterCredentialVerifier.Present(ctx, r, signature, exporter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation presentation refused: "+r.Operation+" "+federationCause(err))
	}
	return out, err
}

type federationServices struct {
	connectorlifecycle.Runners
	peers *federationPeers
}

// Bootstrap enrolls generation 1 for one claimed slot (ADR-193 step 3).
func (s federationServices) Bootstrap(ctx context.Context, region *connectorlifecycle.Region, r value.ClusterBootstrapRequest, key ed25519.PublicKey) (value.ClusterBootstrapResult, error) {
	p := s.peers
	if p == nil || p.bootstrap == nil || r.InstallationID != p.c.InstallationID || r.RootID != p.c.PermissionRootID {
		return value.ClusterBootstrapResult{}, value.ErrDenied
	}
	out, err := p.bootstrap.Activate(ctx, r, key, func(ctx context.Context, e value.Enrollment) (value.ClusterBootstrapSource, error) {
		return p.stage(ctx, region, e)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation bootstrap failed: "+federationCause(err))
	}
	return out, err
}

// stage binds the conversation to the claimed slot and stages the regional
// source under the hub-decided backing: the root's stored backing, or the
// deployment's initial backing before the first staging.
func (s *federationPeers) stage(ctx context.Context, region *connectorlifecycle.Region, e value.Enrollment) (value.ClusterBootstrapSource, error) {
	var zero value.ClusterBootstrapSource
	if err := region.BindBootstrap(e.Binding); err != nil {
		return zero, value.ErrDenied
	}
	backing, found, err := s.profiles.ReadRootBacking(ctx, s.c.PermissionRootID)
	if err != nil {
		return zero, err
	}
	if !found {
		backing = s.connector.Clone()
	}
	q := backing.Policy
	if q.History == nil || backing.AccountVersion != s.accountVersion || q.RootID != s.c.PermissionRootID || q.InstallationID != s.c.InstallationID {
		return zero, mounts.ErrUnavailable
	}
	pin := fleetapp.ConnectorQualificationPin{InstallationID: q.InstallationID, StoreID: q.StoreID, BackupProfileID: q.BackupProfileID, Qualification: *q.History}
	sources, err := postgres.NewConnectorIdentitySources(ctx, s.pools["connector-source"], s.c.PermissionRootID, e.Binding, pin)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	c, err := fleetapp.ConnectorIdentityObserver{Reader: region, Journal: sources, Qualification: pin, Binding: e.Binding, Now: time.Now, Backing: &backing}.ObserveConfiguration(ctx)
	if err != nil {
		return zero, err
	}
	profile := c.Source.Observation.Profile
	return value.ClusterBootstrapSource{UID: profile.Revision.UID, Generation: profile.Revision.Generation, ProtectionDigest: profile.ProtectionDigest}, nil
}

func (s federationServices) Enroll(ctx context.Context, region *connectorlifecycle.Region, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	out, err := s.Runners.Enroll(ctx, region, id, r)
	if err != nil {
		fmt.Fprintln(os.Stderr, "federation enroll failed: "+federationCause(err))
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
	mux.Handle(contracts.ClusterCredentialPath, f.rotation)
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

// federationOwnerReads composes the hub-api's unchanged owner registry, route
// and protection reads (ADR-172). The guard plan is the identical installed
// one, so a region is answered from the same protection digest; nothing here
// can sign, audit or activate an owner.
func federationOwnerReads(ctx context.Context, c contracts.FederationDeployment, pool *pgxpool.Pool, in *providerInputs) (connectorlifecycle.OwnerReads, *kube.OwnerWorkloadProtection, error) {
	var zero connectorlifecycle.OwnerReads
	o := *c.Owner
	configurations, err := postgres.NewOwnerConfigurations(ctx, pool, c.InstallationID, c.ClusterID, o.Namespace.UID, o.ConfigurationUID)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	current, err := configurations.ReadOwnerConfiguration(ctx)
	if err != nil || !current.Valid(time.Now()) || current.Configuration.Pool.Namespace != o.Namespace.Name {
		return zero, nil, mounts.ErrUnavailable
	}
	registry, err := postgres.NewOwnerEnrollments(ctx, pool, c.InstallationID, c.ClusterID, o.Namespace.UID, o.ConfigurationUID, ownerRandomID)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	control := configuration.NamespaceRef{Name: o.Namespace.Name, UID: o.Namespace.UID}
	observer, err := kube.NewPermissionClient(in.kubernetes("kube-observer.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	probe, err := kube.NewPermissionClient(in.kubernetes("kube-probe.token"), c.ClusterID, control, time.Now)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	owners := current.Configuration.Pool
	guard, err := ownerWorkloadGuard(observer, probe, owners, o)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, owners)
	if err != nil {
		return zero, nil, mounts.ErrUnavailable
	}
	routes := &fleetapp.OwnerRoutes{Configurations: configurations, Endpoints: endpoints, Now: time.Now}
	return connectorlifecycle.OwnerReads{Candidates: registry, ObservationCandidates: registry, Registry: registry, Authenticator: &fleetapp.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: guard, Now: time.Now}}, guard, nil
}
