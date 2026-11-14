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
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	auditapp "asservat.local/asservat/internal/application/audit"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/clustercredential"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/jackc/pgx/v5/pgxpool"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Federation is the ADR-170 hub process for connector-facing duties. It serves
// the ADR-169 lifecycle channel for staged peers with the real SQL duties,
// encrypted audit and connector PKI issuer, and answers ADR-172 owner
// discovery and authentication reads. It holds no browser, MCP, evidence,
// owner-signing or recovery-activation authority.
type Federation struct {
	handler  *connectorlifecycle.Handler
	rotation *clustercredential.Handler
	tls      *tls.Config
	port     int
	closers  []func()
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
	f, err := NewFederation(ctx, files, ids)
	if err != nil {
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
		return federationInputs{}, &fixedStepError{"config", mounts.ErrUnavailable}
	}
	v, err := readServiceIDs(ctx, ids)
	if err != nil {
		return federationInputs{}, err
	}
	return federationInputs{c, v}, nil
}

func validFederationConfig(c contracts.FederationConfig) bool {
	_, pg := servicePostgres(c.Postgres, nil)
	return validServiceScope(c.Name, c.Namespace) && c.Port >= 1 && c.Port <= 65535 && c.Concurrency >= 1 && c.Concurrency <= 16 && pg && validServiceStore(c.AuditStore) && ownerEndpoint(c.OpenBao)
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
	peers := &federationPeers{providers: providers, ids: c.ServiceIDs, pools: pools, mac: mac, accountVersion: accountVersion, recovery: recovery, store: store, seal: providers.Sealer(), open: providers.Opener(), owners: owners, profiles: profiles, offerBacking: federationOfferBacking(c), duties: map[value.ClusterCredentialProfile]federationPeerEntry{}}
	credentials, err := postgres.NewClusterCredentials(startup, pools["cluster-credential"], c.PermissionRootID)
	if err != nil {
		return f, mounts.ErrUnavailable
	}
	if err = federationBootstrap(startup, c.InstallationID, pools, store, peers); err != nil {
		return f, err
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

// federationBootstrap composes the ADR-193 generation-1 activation: the
// claim on the cluster-credential login, its acknowledgement on the separate
// connector-ack login, both encrypted audit records and the 00064 ledger. The
// root backing each staging needs is read from SQL (connector_identity_root).
func federationBootstrap(ctx context.Context, installation string, pools map[string]*pgxpool.Pool, store *objectstore.Store, peers *federationPeers) error {
	claims, err := postgres.NewEnrollmentClaims(ctx, pools["cluster-credential"], installation)
	if err != nil {
		return mounts.ErrUnavailable
	}
	audits, err := postgres.NewEnrollmentClaimAudits(ctx, pools["connector-ack"], installation)
	if err != nil {
		return mounts.ErrUnavailable
	}
	ledger, err := postgres.NewClusterBootstraps(ctx, pools["cluster-credential"], installation)
	if err != nil {
		return mounts.ErrUnavailable
	}
	seal, open := peers.seal, peers.open
	peers.bootstrap = &fleetapp.ClusterBootstrapActivation{Claims: claims, ClaimAudits: audits, ClaimObjects: &objectstore.EnrollmentClaimObjects{Store: store, Seal: seal, Open: open},
		Bootstraps: ledger, Audit: &objectstore.ClusterBootstrapAuditObjects{Store: store, Seal: seal, Open: open}, Policy: value.DefaultClusterCredentialPolicy(), Now: time.Now}
	return nil
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
	// bootstrap is the generation-1 activation (ADR-193).
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
	if p.RootID != s.ids.PermissionRootID || p.InstallationID != s.ids.InstallationID {
		return zero, value.ErrDenied
	}
	profile, backing, err := s.profiles.ReadStagedConnector(ctx, p)
	if err != nil {
		return zero, federationEnrollmentError{"staged-profile", value.ErrDenied} // never staged, suspended or blocked
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
	if p == nil || p.bootstrap == nil || r.InstallationID != p.ids.InstallationID || r.RootID != p.ids.PermissionRootID {
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
// source under the hub-decided root backing stored in SQL; without one the
// bootstrap is refused.
func (s *federationPeers) stage(ctx context.Context, region *connectorlifecycle.Region, e value.Enrollment) (value.ClusterBootstrapSource, error) {
	var zero value.ClusterBootstrapSource
	if err := region.BindBootstrap(e.Binding); err != nil {
		return zero, &fixedStepError{"stage/bind", value.ErrDenied}
	}
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
	sources, err := postgres.NewConnectorIdentitySources(ctx, s.pools["connector-source"], s.ids.PermissionRootID, e.Binding, pin)
	if err != nil {
		return zero, &fixedStepError{"stage/sources", mounts.ErrUnavailable}
	}
	c, err := fleetapp.ConnectorIdentityObserver{Reader: region, Journal: sources, Qualification: pin, Binding: e.Binding, Now: time.Now, Backing: &backing}.ObserveConfiguration(ctx)
	if err != nil {
		return zero, &fixedStepError{"stage/observe", err}
	}
	profile := c.Source.Observation.Profile
	return value.ClusterBootstrapSource{UID: profile.Revision.UID, Generation: profile.Revision.Generation, ProtectionDigest: profile.ProtectionDigest}, nil
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
