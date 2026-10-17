package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

func federationTestDeployment() contracts.FederationDeployment {
	return contracts.FederationDeployment{
		Format: contracts.FederationDeploymentFormat, InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", PermissionRootID: "10000000-0000-4000-8000-000000000003",
		Port: 9446, Concurrency: 2,
		Postgres:   contracts.OwnerPostgresEndpoint{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat", MaxConnections: 1},
		AuditStore: contracts.OwnerAuditStore{Endpoint: "https://s3.example", Region: "us-east-1", Bucket: "audit"},
		KeyService: contracts.FederationKeyService{Endpoint: "https://bao.example", AuditMount: "transit", AuditKey: "audit", PKIMount: "pki", ClientRole: "connector-client", ServerRole: "connector-server"},
	}
}

func TestFederationDeploymentInputsAreClosed(t *testing.T) {
	read := func(c contracts.FederationDeployment) error {
		dir := t.TempDir()
		raw, _ := json.Marshal(c)
		if err := os.WriteFile(filepath.Join(dir, "federation.json"), raw, 0o400); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readFederationDeployment(context.Background(), root)
		return err
	}
	if err := read(federationTestDeployment()); err != nil {
		t.Fatal("valid federation input", err)
	}
	for name, mutate := range map[string]func(*contracts.FederationDeployment){
		"pool above one connection": func(c *contracts.FederationDeployment) { c.Postgres.MaxConnections = 2 },
		"same PKI role for both":    func(c *contracts.FederationDeployment) { c.KeyService.ServerRole = c.KeyService.ClientRole },
		"plain HTTP key service":    func(c *contracts.FederationDeployment) { c.KeyService.Endpoint = "http://bao.example" },
		"root not a UUID":           func(c *contracts.FederationDeployment) { c.PermissionRootID = "root" },
		"unbounded concurrency":     func(c *contracts.FederationDeployment) { c.Concurrency = 17 },
		"other format":              func(c *contracts.FederationDeployment) { c.Format = "asservat-federation-deployment/v0" },
	} {
		c := federationTestDeployment()
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
}

// ADR-172: the owner section is the hub-api's own guard plan, validated by the
// same shared check.
func TestFederationOwnerReadsTakeTheHubAPIGuardPlan(t *testing.T) {
	_, _, owner := ownerInputFixture(t)
	read := func(g *contracts.OwnerGuardInputs) error {
		c := federationTestDeployment()
		c.Owner = g
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "federation.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readFederationDeployment(context.Background(), root)
		return err
	}
	g := owner.Guard()
	if err := read(&g); err != nil {
		t.Fatal("hub-api guard plan refused", err)
	}
	for name, mutate := range map[string]func(*contracts.OwnerGuardInputs){
		"plain HTTP Kubernetes": func(g *contracts.OwnerGuardInputs) { g.Kubernetes.Endpoint = "http://api.synthetic.invalid" },
		"no Kubernetes roots":   func(g *contracts.OwnerGuardInputs) { g.Kubernetes.Roots = nil },
		"namespace not a UUID":  func(g *contracts.OwnerGuardInputs) { g.Namespace.UID = "hub" },
		"no administrators":     func(g *contracts.OwnerGuardInputs) { g.WorkloadGuard.Administrators = nil },
		"duplicate probe": func(g *contracts.OwnerGuardInputs) {
			g.ConfigurationProbes = append(g.ConfigurationProbes, g.ConfigurationProbes...)
		},
		"absent probe list": func(g *contracts.OwnerGuardInputs) { g.ConfigurationProbes = nil },
	} {
		g := owner.Guard()
		mutate(&g)
		if read(&g) == nil {
			t.Fatal("accepted:", name)
		}
	}
}

func TestFederationIssuerDispatchesByUsage(t *testing.T) {
	if _, err := (federationIssuer{}).SignConnectorCredential(context.Background(), value.ConnectorCredentialPermit{Usage: "owner"}, nil); err == nil {
		t.Fatal("unknown usage signed")
	}
}

// ADR-193: the federation starts without a peer list and refuses a pinned one;
// a presented peer of another root or installation is refused before any SQL.
func TestFederationPeersComeFromStagedSQLOnly(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(federationTestDeployment())
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	doc["peers"] = []any{}
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "federation.json"), raw, 0o400); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err = readFederationDeployment(context.Background(), root); err == nil {
		t.Fatal("accepted a pinned peer list")
	}
	c := federationTestDeployment()
	peers := &federationPeers{c: c}
	for _, p := range []value.ClusterCredentialProfile{
		{RootID: "10000000-0000-4000-8000-000000000009", PeerID: c.ClusterID, InstallationID: c.InstallationID, ClusterID: c.ClusterID},
		{RootID: c.PermissionRootID, PeerID: c.ClusterID, InstallationID: "10000000-0000-4000-8000-000000000009", ClusterID: c.ClusterID},
	} {
		if _, err := peers.resolve(context.Background(), p); !errors.Is(err, value.ErrDenied) {
			t.Fatal("foreign peer not refused", err)
		}
	}
}

// ADR-193: Kubernetes-auth provider credentials need the owner guard (their
// refresh proof) and the exact recipe profile.
func TestFederationProviderAuthenticationNeedsOwnerGuardAndExactRecipe(t *testing.T) {
	_, _, owner := ownerInputFixture(t)
	g := owner.Guard()
	c := federationTestDeployment()
	recipe, err := providerconfig.FederationProviderRecipeFor(c, contracts.FederationProviderAuthentication{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1",
		Namespace:        g.Namespace,
		ServiceAccount:   contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(c.InstallationID), UID: "10000000-0000-4000-8000-000000000012"},
		AuditCredentials: contracts.WorkerObjectReference{Name: "federation-audit", UID: "10000000-0000-4000-8000-000000000013"}})
	if err != nil {
		t.Fatal(err)
	}
	read := func(c contracts.FederationDeployment) error {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "federation.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readFederationDeployment(context.Background(), root)
		return err
	}
	c.Owner, c.ProviderAuthentication = &g, &recipe.Profile
	if err = read(c); err != nil {
		t.Fatal("valid provider selection refused", err)
	}
	withoutOwner := c
	withoutOwner.Owner = nil
	if read(withoutOwner) == nil {
		t.Fatal("provider credentials without the owner guard proof")
	}
	changed := c
	profile := recipe.Profile
	profile.RecipeSHA256 = strings.Repeat("0", 64)
	changed.ProviderAuthentication = &profile
	if read(changed) == nil {
		t.Fatal("profile that does not match its recipe")
	}
}
