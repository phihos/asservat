package bootstrap

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func publisherTestConfig() contracts.PublisherConfig {
	store := contracts.ServiceObjectStore{Endpoint: "https://s3.example", Region: "us-east-1", Bucket: "audit"}
	return contracts.PublisherConfig{Name: "asservat", Namespace: "asservat", PollSeconds: 2, Batch: 8,
		Postgres:   contracts.ServicePostgres{Host: "postgres.asservat.svc", Port: 5432, Database: "asservat"},
		AuditStore: store, Evidence: contracts.ServiceObjectStore{Endpoint: store.Endpoint, Region: store.Region, Bucket: "evidence"},
		OpenBao: "https://bao.example", RetentionTopologies: []contracts.ServiceTopology{}}
}

// ADR-181/203: the publisher's Helm inputs are closed and bounded; the key
// service address derives from the name and namespace.
func TestPublisherInputsAreClosedAndBound(t *testing.T) {
	read := func(c contracts.PublisherConfig) (publisherInputs, error) {
		return readPublisherInputs(context.Background(), serviceTestConfigRoot(t, c), serviceTestIDsRoot(t, serviceTestIDs))
	}
	if c, err := read(publisherTestConfig()); err != nil || c.keyService() != "https://asservat-key-service.asservat.svc:9447" {
		t.Fatal("valid publisher input", err)
	}
	for name, mutate := range map[string]func(*contracts.PublisherConfig){
		"poll":              func(c *contracts.PublisherConfig) { c.PollSeconds = 0 },
		"batch":             func(c *contracts.PublisherConfig) { c.Batch = 65 },
		"http evidence":     func(c *contracts.PublisherConfig) { c.Evidence.Endpoint = "http://s3.example" },
		"invalid namespace": func(c *contracts.PublisherConfig) { c.Namespace = "" },
		"no name":           func(c *contracts.PublisherConfig) { c.Name = "" },
		"bad topology cluster": func(c *contracts.PublisherConfig) {
			c.RetentionTopologies = []contracts.ServiceTopology{{TargetClusterID: "x", Name: "t"}}
		},
	} {
		c := publisherTestConfig()
		mutate(&c)
		if _, err := read(c); err == nil {
			t.Fatal("accepted:", name)
		}
	}
}
