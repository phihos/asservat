package connectorlifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

type deliveryServices struct {
	scriptedServices
	cluster   string
	items     int
	stored    string
	unchanged bool
}

func (s *deliveryServices) AccessBindings(ctx context.Context, region *Region) error {
	d, unchanged, err := region.ReadAccessBindings(ctx, s.stored)
	if err != nil {
		return err
	}
	if _, _, err = region.ReadAccessBindings(ctx, s.stored); err == nil {
		return ErrChannel // one delivery per conversation
	}
	s.cluster, s.items, s.unchanged = region.Presented().ClusterID, len(d.Items), unchanged
	return nil
}

type deliveringReader struct {
	localReader
	delivery contracts.AccessBindingDelivery
}

func (d deliveringReader) ReadAccessBindings(context.Context) (contracts.AccessBindingDelivery, error) {
	return d.delivery, nil
}

// ADR-329: the hub asks for the delivery only after the presentation, may
// read more than an ordinary conversation for it, and attributes it to the
// presented cluster.
func TestAccessBindingDeliveryOverRealHTTP2(t *testing.T) {
	services := &deliveryServices{}
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
	open := Opening{Purpose: PurposeAccessBindings, OperationID: "10000000-0000-4000-8000-000000000008", Request: request}
	// About 4 MiB: above an ordinary conversation's read bound.
	spec, _ := json.Marshal(map[string]string{"pad": strings.Repeat("x", 4<<10)})
	delivery := contracts.AccessBindingDelivery{ResourceVersion: "7"}
	for range 1000 {
		delivery.Items = append(delivery.Items, contracts.DeliveredAccessBinding{Namespace: "payments", NamespaceUID: "ns", Name: "b", UID: "u", ResourceVersion: "1", Generation: 1, Spec: spec})
	}
	result, err := client.Run(context.Background(), open, deliveringReader{delivery: delivery})
	if err != nil || result.Kind != "result" || services.items != 1000 || services.cluster != process.Binding.ClusterID {
		t.Fatal("delivery", result.Kind, err, services.items, services.cluster)
	}
	// With the hub's stored digest equal to the connector's, nothing is sent.
	services.stored, services.items = delivery.Digest(), 0
	if result, err = client.Run(context.Background(), open, deliveringReader{delivery: delivery}); err != nil || result.Kind != "result" || !services.unchanged || services.items != 0 {
		t.Fatal("unchanged delivery", result.Kind, err, services.unchanged, services.items)
	}
	services.stored = "0000"
	if result, err = client.Run(context.Background(), open, deliveringReader{delivery: delivery}); err != nil || services.unchanged || services.items != 1000 {
		t.Fatal("changed delivery", err, services.unchanged, services.items)
	}
	services.stored = ""
	// A connector without the reader answers with an error.
	services.items = 0
	if _, err = client.Run(context.Background(), open, localReader{}); err == nil || services.items != 0 {
		t.Fatal("delivery without a local reader", err)
	}
	// A hub without the service refuses the purpose.
	plain, err := NewHandler(&acceptTokens{}, &scriptedServices{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = plain
	if result, err = client.Run(context.Background(), open, deliveringReader{delivery: delivery}); err != nil || result.Kind != "failure" {
		t.Fatal("hub without the service", result.Kind, err)
	}
}
