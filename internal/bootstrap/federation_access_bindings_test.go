package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

type digestEnrollmentKeys struct{}

func (digestEnrollmentKeys) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	return sha256.Sum256(csr), nil
}

// lineagePresenter stands in for the SQL lineage: it authenticates the
// signature placeholder and names the lineage's cluster, not the request's.
type lineagePresenter struct{ cluster string }

func (p lineagePresenter) Present(_ context.Context, r value.ClusterCredentialRequest, sig, _ []byte) (value.ClusterCredentialPresentation, error) {
	if len(sig) != 3 {
		return value.ClusterCredentialPresentation{}, value.ErrClusterCredentialDenied
	}
	profile := r.Profile
	profile.ClusterID = p.cluster
	now := time.Now()
	return value.ClusterCredentialPresentation{Profile: profile, LineageID: "10000000-0000-4000-8000-000000000009", Operation: r.Operation, Generation: 1, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}

type recordedBindings struct {
	stored []configuration.RemoteBindings
}

func (r *recordedBindings) StoreRemoteBindings(_ context.Context, d configuration.RemoteBindings) error {
	r.stored = append(r.stored, d)
	return nil
}

type staticBindings struct {
	d contracts.AccessBindingDelivery
}

func (s staticBindings) AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error) {
	return s.d, nil
}

type noLocal struct{ connectorlifecycle.Local }

// ADR-329: the federation stores a delivery under the cluster its credential
// lineage authenticated, never the hub cluster's, validating every spec.
func TestFederationAttributesAccessBindingsToPresentedCluster(t *testing.T) {
	const (
		hub    = "10000000-0000-4000-8000-0000000000a1"
		remote = "10000000-0000-4000-8000-0000000000a2"
		root   = "10000000-0000-4000-8000-000000000007"
		inst   = "10000000-0000-4000-8000-000000000001"
	)
	decoder, err := kube.NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	store := &recordedBindings{}
	ids := contracts.ServiceIDs{InstallationID: inst, ClusterID: hub, PermissionRootID: root}
	services := federationServices{peers: &federationPeers{ids: ids}, bindings: &federationBindings{decoder, store}}
	run := func(lineageCluster string) (connectorlifecycle.HubFrame, error) {
		h, err := connectorlifecycle.NewHandler(lineagePresenter{lineageCluster}, digestEnrollmentKeys{}, services, 2)
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
		client, err := connectorlifecycle.NewClient(server.URL, "example.com", roots)
		if err != nil {
			t.Fatal(err)
		}
		// The process binding claims the lineage's cluster, as the real one must.
		process := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: inst, ClusterID: lineageCluster, IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}, PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
		request := value.ConnectorProcessRequest{Process: process, ClientCSRDER: make([]byte, 64), ServerCSRDER: append(make([]byte, 63), 1)}
		ck, sk := sha256.Sum256(request.ClientCSRDER), sha256.Sum256(request.ServerCSRDER)
		spec, _ := json.Marshal(map[string]any{"reason": "synthetic fixture", "effect": "Allow", "roles": []string{"evidence-reader"}, "subjects": []any{map[string]string{"kind": "Group", "issuer": "https://id.example.test", "id": "team-a"}}})
		delivery := contracts.AccessBindingDelivery{ResourceVersion: "9", Items: []contracts.DeliveredAccessBinding{{Namespace: "payments", NamespaceUID: "payments-uid", Name: "readers", UID: "b-1", ResourceVersion: "3", Generation: 1, Spec: spec}}}
		return client.Run(context.Background(), func([]byte) (connectorlifecycle.Opening, error) {
			w := contracts.ClusterCredentialWire{Format: contracts.ClusterCredentialWireFormat, Operation: value.ClusterRenewal, RootID: root, PeerID: process.Binding.PeerID, InstallationID: inst, ClusterID: lineageCluster, Generation: 1, PodUID: process.PodUID, ProcessEpoch: process.ProcessEpoch, ClientKey: ck[:], ServerKey: sk[:], RequestedAt: time.Now().UTC().Truncate(time.Microsecond), Signature: []byte{1, 2, 3}}
			return connectorlifecycle.Opening{Presentation: w, Purpose: connectorlifecycle.PurposeAccessBindings, OperationID: "10000000-0000-4000-8000-000000000008", Request: request}, nil
		}, deliveringLocal{noLocal{}, staticBindings{delivery}})
	}
	result, err := run(remote)
	if err != nil || result.Kind != "result" || len(store.stored) != 1 {
		t.Fatal("delivery", result.Kind, err, len(store.stored))
	}
	d := store.stored[0]
	if d.ClusterID != remote || len(d.Bindings) != 1 || d.Bindings[0].Scope.ClusterID != remote || d.Bindings[0].Invalid || d.ObservedAt.IsZero() || !d.Valid() {
		t.Fatalf("stored %+v", d)
	}
	// The hub cluster's own connector is observed directly, never delivered.
	if result, err = run(hub); err != nil || result.Kind != "failure" || len(store.stored) != 1 {
		t.Fatal("hub cluster delivery accepted", result.Kind, err)
	}
}
