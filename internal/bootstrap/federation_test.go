package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

func federationTestConfig() contracts.FederationConfig {
	return contracts.FederationConfig{Port: 9446, Concurrency: 2, Namespace: "asservat", OwnerConfiguration: "asservat-owner-source",
		Postgres:   contracts.ServicePostgres{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat"},
		AuditStore: contracts.ServiceObjectStore{Endpoint: "https://s3.example", Region: "us-east-1", Bucket: "audit"},
		OpenBao:    "https://bao.example", AuditMount: "transit", AuditKey: "audit", PKIMount: "pki", ClientRole: "connector-client", ServerRole: "connector-server",
		Provider: contracts.ServiceProviderLogin{AuthMount: "kubernetes", Audience: "asservat-federation", ServiceAccount: "asservat-federation",
			Roles: map[string]string{"audit-wrap": "a", "audit-unwrap": "b", "client-sign": "c", "server-sign": "d"}}}
}

// The federation's Helm inputs are closed: unknown fields, unbounded limits
// and ambiguous roles stop it before any connection.
func TestFederationInputsAreClosed(t *testing.T) {
	read := func(v any) error {
		_, err := readFederationInputs(context.Background(), serviceTestConfigRoot(t, v), serviceTestIDsRoot(t, serviceTestIDs))
		return err
	}
	if c, err := readFederationInputs(context.Background(), serviceTestConfigRoot(t, federationTestConfig()), serviceTestIDsRoot(t, serviceTestIDs)); err != nil || c.PermissionRootID != serviceTestIDs.PermissionRootID {
		t.Fatal("valid federation input", err)
	}
	for name, mutate := range map[string]func(*contracts.FederationConfig){
		"same PKI role for both":  func(c *contracts.FederationConfig) { c.ServerRole = c.ClientRole },
		"plain HTTP provider":     func(c *contracts.FederationConfig) { c.OpenBao = "http://bao.example" },
		"unbounded concurrency":   func(c *contracts.FederationConfig) { c.Concurrency = 17 },
		"no owner configuration":  func(c *contracts.FederationConfig) { c.OwnerConfiguration = "" },
		"invalid namespace":       func(c *contracts.FederationConfig) { c.Namespace = "Hub_NS" },
		"audit mount is PKI":      func(c *contracts.FederationConfig) { c.AuditMount = c.PKIMount },
		"plain HTTP audit store":  func(c *contracts.FederationConfig) { c.AuditStore.Endpoint = "http://s3.example" },
		"postgres port out of 16": func(c *contracts.FederationConfig) { c.Postgres.Port = 70000 },
	} {
		c := federationTestConfig()
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
	raw, _ := json.Marshal(federationTestConfig())
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["peers"] = []any{}
	if read(doc) == nil {
		t.Fatal("accepted a pinned peer list")
	}
	if _, err := readFederationInputs(context.Background(), serviceTestConfigRoot(t, federationTestConfig()), serviceTestConfigRoot(t, map[string]string{})); err == nil {
		t.Fatal("started without generated IDs")
	}
}

// The owner protection is the deterministic platform digest of the pool's
// own Deployment, bounded to five seconds.
func TestFederationOwnerProtectionIsThePlatformDigest(t *testing.T) {
	now := time.Now()
	u := serviceTestIDs.IssuerEpoch
	pool := value.OwnerPool{InstallationID: serviceTestIDs.InstallationID, ClusterID: serviceTestIDs.ClusterID, IssuerEpoch: u, Namespace: "asservat", NamespaceUID: u, Service: "asservat-hub-api", ServiceUID: u, Deployment: "asservat-hub-api", DeploymentUID: u, ServiceAccount: "asservat-hub-api", AccountUID: u, Port: 8443}
	got, err := platformOwnerProtection{func() time.Time { return now }}.ReadOwnerProtection(context.Background(), pool)
	if err != nil || got.Pool != pool || got.Digest != artifact.Digest(contracts.PlatformWorkloadDigest(pool.ClusterID, pool.Namespace, pool.Deployment)) || got.FreshUntil.Sub(got.ObservedAt) != 5*time.Second {
		t.Fatal("owner protection", got, err)
	}
	if _, err = (platformOwnerProtection{time.Now}).ReadOwnerProtection(context.Background(), value.OwnerPool{}); err == nil {
		t.Fatal("invalid pool protected")
	}
}

func TestFederationIssuerDispatchesByUsage(t *testing.T) {
	if _, err := (federationIssuer{}).SignConnectorCredential(context.Background(), value.ConnectorCredentialPermit{Usage: "owner"}, nil); err == nil {
		t.Fatal("unknown usage signed")
	}
}

// ADR-193: a presented peer of another root or installation is refused
// before any SQL.
func TestFederationPeersComeFromStagedSQLOnly(t *testing.T) {
	c := serviceTestIDs
	peers := &federationPeers{ids: c}
	for _, p := range []value.ClusterCredentialProfile{
		{RootID: "10000000-0000-4000-8000-000000000009", PeerID: c.ClusterID, InstallationID: c.InstallationID, ClusterID: c.ClusterID},
		{RootID: c.PermissionRootID, PeerID: c.ClusterID, InstallationID: "10000000-0000-4000-8000-000000000009", ClusterID: c.ClusterID},
	} {
		if _, err := peers.resolve(context.Background(), p); !errors.Is(err, value.ErrDenied) {
			t.Fatal("foreign peer not refused", err)
		}
	}
}

// The log consumes fixed local stages and closed classes, never provider text.
func TestFederationEnrollmentDiagnosticNamesCompositionBoundary(t *testing.T) {
	private := errors.New("synthetic private provider error")
	err := federationEnrollmentError{"audit-journal", private}
	if federationEnrollmentStep(err) != "resolve/audit-journal" || federationCause(err) != "unavailable" || !errors.Is(err, private) {
		t.Fatal("composition boundary or error class lost")
	}
	if strings.Contains(err.Error(), "synthetic") {
		t.Fatal("provider text entered fixed diagnostic")
	}
}
