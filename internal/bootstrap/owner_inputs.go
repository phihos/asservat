package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/rest"
)

var ownerProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var ownerDNSName = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// providerInputs is shared only by protected installation bootstraps. It
// carries provider connections, never accepted configuration or user authority.
type providerInputs struct {
	mu         sync.Mutex
	transports []http.RoundTripper
	files      *os.Root
	// dir, when set, is a subdirectory of a kubelet projected volume mounted
	// at files. The kubelet replaces the volume's data directory whenever it
	// refreshes any item (projected tokens every few minutes) and deletes the
	// old one, so a root opened on the subdirectory would keep pointing at
	// deleted files. Every read resolves dir again through the stable root.
	dir                string
	kubernetesEndpoint contracts.OwnerProviderEndpoint
	postgresEndpoint   contracts.OwnerPostgresEndpoint
}

// read reads one projected file, resolving dir on every call.
func (s *providerInputs) read(ctx context.Context, name string, limit int64) ([]byte, error) {
	if s.dir != "" {
		name = s.dir + "/" + name
	}
	return mounts.Read(ctx, s.files, name, limit)
}
type ownerInputs struct {
	*providerInputs
	config contracts.OwnerDeployment
}

func ownerEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && len(endpoint) <= 2048 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && !strings.Contains(endpoint, "#") && u.RawPath == "" && (u.Path == "" || u.Path == "/")
}

// ownerDialAddress is a plain host:port a regional process dials.
func ownerDialAddress(s string) bool {
	host, port, err := net.SplitHostPort(s)
	number, perr := strconv.Atoi(port)
	return err == nil && perr == nil && host != "" && len(host) <= 253 && number >= 1 && number <= 65535 && !strings.ContainsAny(host, "/\\@?#% \t\r\n")
}
func ownerHTTP(endpoint string, raw [][]byte) (*http.Client, error) {
	if !ownerEndpoint(endpoint) {
		return nil, mounts.ErrUnavailable
	}
	roots, _, err := mtls.OwnerTrustRoots(raw, time.Now())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return mounts.ErrUnavailable }, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxIdleConns: 4, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 16, DisableCompression: true}}, nil
}

func readOwnerInputs(ctx context.Context, files *os.Root) (*ownerInputs, error) {
	b, err := mounts.Read(ctx, files, "deployment.json", contracts.OwnerDeploymentMaxBytes)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerDeployment(bytes.NewReader(b))
	if err != nil || validateOwnerDeployment(c) != nil {
		return nil, mounts.ErrUnavailable
	}
	return &ownerInputs{providerInputs: &providerInputs{files: files, kubernetesEndpoint: c.Kubernetes, postgresEndpoint: c.Postgres}, config: c}, nil
}

// ownerInputCheck names the failed owner input check; the name is fixed text,
// never an input value, so it can appear in an installer stop message.
type ownerInputCheck string

func (e ownerInputCheck) Error() string     { return "owner input check " + string(e) }
func (e ownerInputCheck) FixedStep() string { return string(e) }
func (e ownerInputCheck) Unwrap() error     { return mounts.ErrUnavailable }

// validateOwnerDeployment is the owner's pure input check of a projected input.
func validateOwnerDeployment(c contracts.OwnerDeployment) error { return validateOwnerInput(c, true) }

// validateUnprojectedOwnerDeployment is the same check before the owner
// projection attaches the observation activation (ADR-194): the installer runs
// it on a derived promoted input, and the projection then binds the activation.
func validateUnprojectedOwnerDeployment(c contracts.OwnerDeployment) error {
	return validateOwnerInput(c, false)
}

func validateOwnerInput(c contracts.OwnerDeployment, projected bool) error {
	var err error
	if c.Format != contracts.OwnerDeploymentFormat || !authorization.UUID(c.InstallationID) || !authorization.UUID(c.ClusterID) || !authorization.UUID(c.PermissionRootID) || !authorization.UUID(c.Namespace.UID) || !authorization.UUID(c.ConfigurationUID) || !identity.Text(c.Namespace.Name, 63) || c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections {
		return ownerInputCheck("identity")
	}
	if !ownerProviderName.MatchString(c.KeyService.AuditMount) || !ownerProviderName.MatchString(c.KeyService.AuditKey) || !ownerProviderName.MatchString(c.KeyService.PKIMount) || !ownerProviderName.MatchString(c.KeyService.ServerRole) || !ownerProviderName.MatchString(c.KeyService.ClientRole) || c.KeyService.ServerRole == c.KeyService.ClientRole || c.KeyService.AuditMount == c.KeyService.PKIMount || !identity.Text(c.AuditStore.Region, 128) || !identity.Text(c.AuditStore.Bucket, 63) {
		return ownerInputCheck("key-service")
	}
	for _, ep := range []contracts.OwnerProviderEndpoint{c.Kubernetes, {Endpoint: c.AuditStore.Endpoint, Roots: c.AuditStore.Roots}, {Endpoint: c.KeyService.Endpoint, Roots: c.KeyService.Roots}} {
		if !ownerEndpoint(ep.Endpoint) {
			return ownerInputCheck("endpoint")
		}
		if _, _, err = mtls.OwnerTrustRoots(ep.Roots, time.Now()); err != nil {
			return ownerInputCheck("endpoint-roots")
		}
	}
	if !identity.Text(c.Postgres.Database, 63) || c.Postgres.Port < 1 || c.Postgres.Port > 65535 || c.Postgres.MaxConnections < 1 || c.Postgres.MaxConnections > 4 {
		return ownerInputCheck("postgres")
	}
	if _, err = netip.ParseAddr(c.Postgres.Host); err != nil && !ownerDNSName.MatchString(c.Postgres.Host) {
		return ownerInputCheck("postgres-host")
	}
	if _, _, err = mtls.OwnerTrustRoots(c.Postgres.Roots, time.Now()); err != nil {
		return ownerInputCheck("postgres-roots")
	}
	if !validOwnerGuard(c.Guard()) {
		return ownerInputCheck("guard")
	}
	// ADR-182: an installed (provider-authenticated) owner may be promoted
	// with Native and Public; the legacy layout keeps them exclusive.
	if c.ProviderAuthentication != nil && (c.Observation == nil || projected && c.Observation.Activation == nil || c.Observation.Activation != nil && c.Observation.Activation.Input.OwnerLayout != contracts.OwnerProviderInstalledLayout || kms.ValidateOwnerProviderAuthentication(c, *c.ProviderAuthentication, time.Now()) != nil) {
		return ownerInputCheck("provider-authentication")
	}
	if c.Observation != nil && (projected && c.Observation.Activation == nil || c.Observation.Activation != nil && !kube.OwnerIdentityActivationBound(c, *c.Observation.Activation)) {
		return ownerInputCheck("observation-activation")
	}
	if validateOwnerNativeInputs(c.Native, c.ClusterID, c.ProviderAuthentication != nil) != nil || validateOwnerObservationInputs(c.Observation, projected) != nil || c.Native != nil && c.Observation != nil && c.ProviderAuthentication == nil {
		return ownerInputCheck("native-observation")
	}
	if p := c.Public; p != nil {
		// Six owner pools plus the hot public purposes must leave cold slots
		// within the per-replica governor (ADR-177).
		if _, ok := publicContextHost(p.Origin); !ok || p.Format != contracts.OwnerPublicDeploymentFormat || c.Native == nil || 6*int(c.Postgres.MaxConnections)+len(hubAPIHotPurposes) >= contracts.SQLConnectionsPerHubReplica {
			return ownerInputCheck("public-origin")
		}
		if !authorization.UUID(p.BrowserRootID) || !capacityRuntimeReference(p.BrowserSettings) || !capacityRuntimeReference(p.IdentitySettings) || p.BrowserSettings.Name == p.IdentitySettings.Name || !identity.Text(p.BrowserAudience, 256) || !ownerProviderName.MatchString(p.SessionTransit.Mount) || !ownerProviderName.MatchString(p.SessionTransit.Key) || p.SessionTransit.Mount == c.KeyService.AuditMount || p.SessionTransit.Mount == c.KeyService.PKIMount {
			return ownerInputCheck("public-identity")
		}
		if _, _, err = mtls.OwnerTrustRoots(p.ProviderRoots, time.Now()); err != nil {
			return ownerInputCheck("provider-roots")
		}
		// The installed layout fixes the public port and pins its public provider
		// recipe; the legacy layout reads token files and has no recipe.
		installed := c.ProviderAuthentication != nil
		// ADR-194: the installed layout also names the immutable public runtime
		// projection, which startup compares with the mounted public root.
		if installed && (p.Port != contracts.OwnerInstalledPublicPort || providerconfig.ValidateOwnerPublicProviderRecipe(c, *c.ProviderAuthentication, time.Now()) != nil ||
			p.RuntimeProjection.Name != contracts.PublicRuntimeProjectionName(c.InstallationID) || !authorization.UUID(p.RuntimeProjection.UID)) || !installed && p.ProviderRecipeSHA256 != "" {
			return ownerInputCheck("public-installed")
		}
		// ADR-193: issuance needs the installed layout's pinned channel role.
		if f := p.Fleet; f != nil && (!installed || !capacityRuntimeReference(f.Settings) || !capacityRuntimeGuard(f.SettingsGuard) || !identity.Text(f.DeliveryProfile, 64) ||
			providerconfig.ValidateOwnerFleetProviderRecipe(c, *c.ProviderAuthentication, time.Now()) != nil) {
			return ownerInputCheck("fleet")
		}
		if p.Port < 1024 || p.Port > 65535 || p.Port == 9443 || p.Port == contracts.OwnerInstalledNativePort || !identity.Text(p.Version, 64) || p.OperationConcurrency < 1 || p.OperationConcurrency > 64 || p.MCPPerIdentity < 1 || p.MCPPerIdentity > p.OperationConcurrency || p.DownloadConcurrency < 1 || p.DownloadConcurrency > 64 || p.DownloadsPerIdentity < 1 || p.DownloadsPerIdentity > p.DownloadConcurrency || p.DownloadMaxSeconds < 1 || p.DownloadMaxSeconds > 86400 {
			return ownerInputCheck("public-limits")
		}
	}
	return nil
}

func (s *providerInputs) token(name string) kms.TokenSource {
	return func(ctx context.Context) ([]byte, error) {
		b, err := s.read(ctx, name, 16384)
		if err != nil || !kms.ValidProviderToken(b) {
			clear(b)
			return nil, mounts.ErrUnavailable
		}
		return b, nil
	}
}

type mountedOwnerPodToken struct{ inputs *ownerInputs }

func (s mountedOwnerPodToken) ReadOwnerPodToken(ctx context.Context) ([]byte, error) {
	b, err := s.inputs.token("owner-pod.token")(ctx)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

type ownerBearerTransport struct {
	http.RoundTripper
	token kms.TokenSource
}

func (s ownerBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b, err := s.token(r.Context())
	defer clear(b)
	if err != nil || r.Context().Err() != nil || !contracts.ValidWorkerToken(b) {
		return nil, mounts.ErrUnavailable
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return s.RoundTripper.RoundTrip(r)
}
func (s *providerInputs) kubernetes(name string) *rest.Config {
	return s.kubernetesToken(s.token(name))
}

// The bootstrap observation source is concrete and installation-owned; no
// public request may supply a token callback. Other credentials retain mounted
// per-request reads and their original purpose.
func (s *providerInputs) kubernetesToken(source kms.TokenSource) *rest.Config {
	var ca bytes.Buffer
	for _, der := range s.kubernetesEndpoint.Roots {
		_ = pem.Encode(&ca, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return &rest.Config{Host: s.kubernetesEndpoint.Endpoint, TLSClientConfig: rest.TLSClientConfig{CAData: ca.Bytes()}, WrapTransport: func(t http.RoundTripper) http.RoundTripper {
		s.mu.Lock()
		s.transports = append(s.transports, t)
		s.mu.Unlock()
		return ownerBearerTransport{t, source}
	}}
}

func (s *providerInputs) sqlCredential(ctx context.Context, name string) (contracts.OwnerSQLCredential, error) {
	var zero contracts.OwnerSQLCredential
	b, err := s.read(ctx, name, 16<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerSQLCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.Username, 63) || len(c.Password) < 1 || len(c.Password) > 4096 || strings.ContainsRune(c.Password, 0) {
		return zero, mounts.ErrUnavailable
	}
	return c, nil
}

// Bootstrap never parses a secret-bearing DSN or imports PG* settings. A fixed
// harmless parse initializes pgx's internal invariants before explicit fields
// replace it; TLS and all fallback/runtime settings are independently supplied.
func (s *providerInputs) sqlConfig(ctx context.Context, name string) (*pgxpool.Config, error) {
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PG") {
			return nil, mounts.ErrUnavailable
		}
	}
	c, err := pgxpool.ParseConfig("host=localhost port=1 user=unused password=unused dbname=unused sslmode=disable")
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	p := s.postgresEndpoint
	roots, _, err := mtls.OwnerTrustRoots(p.Roots, time.Now())
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	credential, err := s.sqlCredential(ctx, name)
	if err != nil {
		return nil, err
	}
	c.ConnConfig.Host, c.ConnConfig.Port, c.ConnConfig.Database = p.Host, uint16(p.Port), p.Database
	c.ConnConfig.User, c.ConnConfig.Password = credential.Username, credential.Password
	c.ConnConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.Host, RootCAs: roots}
	c.ConnConfig.Fallbacks = nil
	c.ConnConfig.RuntimeParams = map[string]string{"application_name": "asservat-owner"}
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	c.ConnConfig.Tracer = nil
	c.ConnConfig.ValidateConnect, c.ConnConfig.AfterConnect = nil, nil
	c.MaxConns, c.MinConns = p.MaxConnections, 0
	c.MaxConnLifetime, c.MaxConnLifetimeJitter, c.MaxConnIdleTime = 5*time.Minute, 30*time.Second, 30*time.Second
	c.BeforeConnect = func(ctx context.Context, c *pgx.ConnConfig) error {
		next, err := s.sqlCredential(ctx, name)
		if err != nil || next.Username != credential.Username {
			// Named so a failed connection says it was the credential re-read.
			return &fixedStepError{"credential", mounts.ErrUnavailable}
		}
		c.Password = next.Password
		return nil
	}
	return c, nil
}

type mountedStorage struct{ inputs *providerInputs }

func (s mountedStorage) Retrieve(ctx context.Context) (aws.Credentials, error) {
	var zero aws.Credentials
	b, err := s.inputs.read(ctx, "audit-storage.json", 32<<10)
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b))
	if err != nil || !identity.Text(c.AccessKeyID, 256) || !identity.Text(c.SecretAccessKey, 4096) || (c.SessionToken != "" && !identity.Text(c.SessionToken, 16384)) {
		return zero, mounts.ErrUnavailable
	}
	return aws.Credentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Source: "protected-owner-projection"}, nil
}

func (s *providerInputs) closeHTTP() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.transports {
		if c, ok := t.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
	}
}
