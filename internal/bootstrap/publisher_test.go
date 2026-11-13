package bootstrap

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func publisherTestConfig() contracts.PublisherConfig {
	store := contracts.ServiceObjectStore{Endpoint: "https://s3.example", Region: "us-east-1", Bucket: "audit"}
	return contracts.PublisherConfig{Namespace: "asservat", PollSeconds: 2, Batch: 8,
		Postgres:   contracts.ServicePostgres{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat"},
		AuditStore: store, Evidence: contracts.ServiceObjectStore{Endpoint: store.Endpoint, Region: store.Region, Bucket: "evidence"},
		OpenBao: "https://bao.example", AuditMount: "transit", AuditKey: "publisher-audit", VerifierPKIMount: "worker-pki", VerifierRole: "verifier",
		KeyService: "https://asservat-key-service.asservat.svc:9447", KeyID: "artifact",
		Provider: contracts.ServiceProviderLogin{AuthMount: "kubernetes", Audience: "asservat-publisher", ServiceAccount: "asservat-publisher",
			Roles: map[string]string{"audit-wrap": "a", "audit-unwrap": "b", "verifier-sign": "c"}},
		ClusterCatalog: "asservat-cluster-catalog", RetentionTopologies: []contracts.ServiceTopology{}}
}

// ADR-181/203: the publisher's Helm inputs are closed and bounded.
func TestPublisherInputsAreClosedAndBound(t *testing.T) {
	read := func(c contracts.PublisherConfig) error {
		_, err := readPublisherInputs(context.Background(), serviceTestConfigRoot(t, c), serviceTestIDsRoot(t, serviceTestIDs))
		return err
	}
	if err := read(publisherTestConfig()); err != nil {
		t.Fatal("valid publisher input", err)
	}
	for name, mutate := range map[string]func(*contracts.PublisherConfig){
		"poll":               func(c *contracts.PublisherConfig) { c.PollSeconds = 0 },
		"batch":              func(c *contracts.PublisherConfig) { c.Batch = 65 },
		"http evidence":      func(c *contracts.PublisherConfig) { c.Evidence.Endpoint = "http://s3.example" },
		"plain key service":  func(c *contracts.PublisherConfig) { c.KeyService = "http://keys.example" },
		"unsafe key ID":      func(c *contracts.PublisherConfig) { c.KeyID = "../artifact" },
		"audit mount is PKI": func(c *contracts.PublisherConfig) { c.AuditMount = c.VerifierPKIMount },
		"no catalog":         func(c *contracts.PublisherConfig) { c.ClusterCatalog = "" },
		"invalid namespace":  func(c *contracts.PublisherConfig) { c.Namespace = "" },
		"bad verifier role":  func(c *contracts.PublisherConfig) { c.VerifierRole = "a/b" },
		"bad topology cluster": func(c *contracts.PublisherConfig) {
			c.RetentionTopologies = []contracts.ServiceTopology{{TargetClusterID: "x", Name: "t"}}
		},
	} {
		c := publisherTestConfig()
		mutate(&c)
		if read(c) == nil {
			t.Fatal("accepted:", name)
		}
	}
}
