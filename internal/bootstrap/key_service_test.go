package bootstrap

import (
	"context"
	"os"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func keyServiceTestDeployment(t *testing.T) contracts.KeyServiceDeployment {
	t.Helper()
	f, _, l := newRuntimeFixture(t)
	l.Close()
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	roots := [][]byte{f.ca.Raw}
	return contracts.KeyServiceDeployment{Format: contracts.KeyServiceDeploymentFormat, InstallationID: id("01"), ClusterID: id("02"), PermissionRootID: id("03"), Port: 9447,
		Namespace: contracts.WorkerObjectReference{Name: "asservat-keys", UID: id("04")}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid", Roots: roots},
		KeySource: contracts.WorkerObjectReference{Name: "artifact-keys", UID: id("05")}, KeyID: "artifact", RecoveryEpoch: id("06"),
		Postgres:       contracts.OwnerPostgresEndpoint{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat", MaxConnections: 1},
		KeyClientRoots: roots, ConnectorClientRoots: roots, Concurrency: 4}
}

// ADR-176: the key service's inputs are closed; an invalid section stops it.
func TestKeyServiceDeploymentInputsAreClosed(t *testing.T) {
	read := func(c contracts.KeyServiceDeployment) error {
		dir := t.TempDir()
		writeOwnerJSON(t, dir, "key-service.json", c)
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		_, err = readKeyServiceDeployment(context.Background(), root)
		return err
	}
	if err := read(keyServiceTestDeployment(t)); err != nil {
		t.Fatal("valid key service input", err)
	}
	for name, mutate := range map[string]func(*contracts.KeyServiceDeployment){
		"pool above one connection": func(c *contracts.KeyServiceDeployment) { c.Postgres.MaxConnections = 2 },
		"no connector roots":        func(c *contracts.KeyServiceDeployment) { c.ConnectorClientRoots = nil },
		"epoch not a UUID":          func(c *contracts.KeyServiceDeployment) { c.RecoveryEpoch = "epoch" },
		"unsafe key ID":             func(c *contracts.KeyServiceDeployment) { c.KeyID = "../root" },
		"no key-client roots":       func(c *contracts.KeyServiceDeployment) { c.KeyClientRoots = nil },
		"plain HTTP Kubernetes":     func(c *contracts.KeyServiceDeployment) { c.Kubernetes.Endpoint = "http://api.synthetic.invalid" },
		"unbounded concurrency":     func(c *contracts.KeyServiceDeployment) { c.Concurrency = 65 },
		"other format":              func(c *contracts.KeyServiceDeployment) { c.Format = "asservat-key-service-deployment/v0" },
	} {
		c := keyServiceTestDeployment(t)
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
}
