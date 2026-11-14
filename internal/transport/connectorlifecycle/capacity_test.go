package connectorlifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

type capacityServices struct {
	scriptedServices
	cluster    string
	namespaces int
	stored     string
	unchanged  bool
}

func (s *capacityServices) Capacity(ctx context.Context, region *Region) error {
	d, unchanged, err := region.ReadCapacity(ctx, s.stored)
	if err != nil {
		return err
	}
	if _, _, err = region.ReadCapacity(ctx, s.stored); err == nil {
		return ErrChannel // one delivery per conversation
	}
	if _, _, err = region.ReadAccessBindings(ctx, ""); err == nil {
		return ErrChannel // and no AccessBinding request beside it
	}
	s.cluster, s.namespaces, s.unchanged = region.Presented().ClusterID, len(d.Namespaces), unchanged
	return nil
}

type capacityReader struct {
	localReader
	delivery contracts.CapacityDelivery
}

func (d capacityReader) ReadCapacity(context.Context) (contracts.CapacityDelivery, error) {
	return d.delivery, nil
}

// ADR-331: the capacity delivery follows the AccessBinding delivery's
// rules: asked after the presentation, attributed to the presented cluster,
// refused by a connector without the reader and by a hub without the
// service.
func TestCapacityDeliveryOverRealHTTP2(t *testing.T) {
	services := &capacityServices{}
	h, err := NewHandler(&acceptTokens{}, services, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(server.URL, "example.com", roots, syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	process := value.ConnectorProcessIdentity{Binding: localReader{}.binding(), PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
	request := value.ConnectorProcessRequest{Process: process, ClientCSRDER: make([]byte, 64), ServerCSRDER: append(make([]byte, 63), 1)}
	open := Opening{Purpose: PurposeCapacity, OperationID: "10000000-0000-4000-8000-000000000008", Request: request}
	delivery := contracts.CapacityDelivery{}
	for range 300 {
		delivery.Namespaces = append(delivery.Namespaces, contracts.DeliveredCapacityNamespace{Name: "payments", UID: "ns", ResourceVersion: "1", Labels: map[string]string{"team": "payments"},
			Workloads: []contracts.DeliveredCapacityWorkload{{Kind: "Deployment", Name: "api", UID: "w", ResourceVersion: "2"}}})
	}
	result, err := client.Run(context.Background(), open, capacityReader{delivery: delivery})
	if err != nil || result.Kind != "result" || services.namespaces != 300 || services.cluster != process.Binding.ClusterID {
		t.Fatal("delivery", result.Kind, err, services.namespaces, services.cluster)
	}
	services.stored, services.namespaces = delivery.Digest(), 0
	if result, err = client.Run(context.Background(), open, capacityReader{delivery: delivery}); err != nil || !services.unchanged || services.namespaces != 0 {
		t.Fatal("unchanged delivery", result.Kind, err)
	}
	services.stored = ""
	if _, err = client.Run(context.Background(), open, localReader{}); err == nil || services.namespaces != 0 {
		t.Fatal("delivery without a local reader", err)
	}
	plain, err := NewHandler(&acceptTokens{}, &scriptedServices{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = plain
	if result, err = client.Run(context.Background(), open, capacityReader{delivery: delivery}); err != nil || result.Kind != "failure" {
		t.Fatal("hub without the service", result.Kind, err)
	}
}
