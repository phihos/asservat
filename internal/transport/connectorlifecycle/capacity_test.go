package connectorlifecycle

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"
	"time"

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
	s.cluster, s.namespaces, s.unchanged = region.Presented().Profile.ClusterID, len(d.Namespaces), unchanged
	return nil
}

type capacityReader struct {
	localReader
	delivery contracts.CapacityDelivery
}

func (d capacityReader) ReadCapacity(context.Context) (contracts.CapacityDelivery, error) {
	return d.delivery, nil
}

// ADR-330: the capacity delivery follows the AccessBinding delivery's
// rules: asked after the presentation, attributed to the presented cluster,
// refused by a connector without the reader and by a hub without the
// service.
func TestCapacityDeliveryOverRealHTTP2(t *testing.T) {
	services := &capacityServices{}
	h, err := NewHandler(&acceptPresenter{}, digestKeys{}, services, 2)
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
	client, err := NewClient(server.URL, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	process := value.ConnectorProcessIdentity{Binding: localReader{}.binding(), PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
	request := value.ConnectorProcessRequest{Process: process, ClientCSRDER: make([]byte, 64), ServerCSRDER: append(make([]byte, 63), 1)}
	clientKey, serverKey := sha256.Sum256(request.ClientCSRDER), sha256.Sum256(request.ServerCSRDER)
	open := func(exporter []byte) (Opening, error) {
		w := contracts.ClusterCredentialWire{Format: contracts.ClusterCredentialWireFormat, Operation: value.ClusterRenewal, RootID: "10000000-0000-4000-8000-000000000007", PeerID: process.Binding.PeerID, InstallationID: process.Binding.InstallationID, ClusterID: process.Binding.ClusterID, Generation: 1, PodUID: process.PodUID, ProcessEpoch: process.ProcessEpoch, ClientKey: clientKey[:], ServerKey: serverKey[:], RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Signature: []byte{1, 2, 3}}
		return Opening{Presentation: w, Purpose: PurposeCapacity, OperationID: "10000000-0000-4000-8000-000000000008", Request: request}, nil
	}
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
	plain, err := NewHandler(&acceptPresenter{}, digestKeys{}, &scriptedServices{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = plain
	if result, err = client.Run(context.Background(), open, capacityReader{delivery: delivery}); err != nil || result.Kind != "failure" {
		t.Fatal("hub without the service", result.Kind, err)
	}
}
