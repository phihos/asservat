package bootstrap

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

func federationTestConfig() contracts.FederationConfig {
	return contracts.FederationConfig{Name: "asservat", Namespace: "asservat", Port: 9446, Concurrency: 2,
		Postgres:        contracts.ServicePostgres{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat"},
		ConnectorTokens: contracts.ConnectorTokens{Audiences: []string{"https://asservat-federation.asservat.svc:9446"}}}
}

// The federation's Helm inputs are closed: unknown fields and unbounded
// limits stop it before any connection. Provider names are derived, never
// configured.
func TestFederationInputsAreClosed(t *testing.T) {
	read := func(v any) error {
		_, err := readFederationInputs(context.Background(), serviceTestConfigRoot(t, v), serviceTestIDsRoot(t, serviceTestIDs))
		return err
	}
	if c, err := readFederationInputs(context.Background(), serviceTestConfigRoot(t, federationTestConfig()), serviceTestIDsRoot(t, serviceTestIDs)); err != nil || c.PermissionRootID != serviceTestIDs.PermissionRootID {
		t.Fatal("valid federation input", err)
	}
	for name, mutate := range map[string]func(*contracts.FederationConfig){
		"no token audience":       func(c *contracts.FederationConfig) { c.ConnectorTokens.Audiences = nil },
		"no name":                 func(c *contracts.FederationConfig) { c.Name = "" },
		"name over 30":            func(c *contracts.FederationConfig) { c.Name = strings.Repeat("a", 31) },
		"invalid namespace":       func(c *contracts.FederationConfig) { c.Namespace = "Hub_NS" },
		"postgres port out of 16": func(c *contracts.FederationConfig) { c.Postgres.Port = 70000 },
	} {
		c := federationTestConfig()
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
	for _, field := range []string{"peers", "auditKey", "provider"} {
		raw, _ := json.Marshal(federationTestConfig())
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		doc[field] = "x"
		if read(doc) == nil {
			t.Fatal("accepted field", field)
		}
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
	if err != nil || got.Pool != pool || got.Digest != artifact.Digest(contracts.WorkloadSourceDigest(pool.ClusterID, pool.Namespace, pool.Deployment)) || got.FreshUntil.Sub(got.ObservedAt) != 5*time.Second {
		t.Fatal("owner protection", got, err)
	}
	if _, err = (platformOwnerProtection{time.Now}).ReadOwnerProtection(context.Background(), value.OwnerPool{}); err == nil {
		t.Fatal("invalid pool protected")
	}
}
