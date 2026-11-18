package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// clusterTokens stands in for the ServiceAccount verifier: it attributes
// every token to one registered cluster.
type clusterTokens struct{ cluster, root, peer, installation string }

func (p clusterTokens) VerifyConnector(context.Context, string) (value.ConnectorCluster, error) {
	return value.ConnectorCluster{RootID: p.root, PeerID: p.peer, InstallationID: p.installation, ClusterID: p.cluster}, nil
}

type recordedBindings struct {
	stored        []configuration.RemoteBindings
	digest        string
	confirmations int
}

func (r *recordedBindings) StoreRemoteBindings(_ context.Context, cluster string, previous time.Time, digest string, bindings []configuration.Binding) error {
	if previous != time.Unix(1700000000, 0) {
		return configuration.ErrChanged
	}
	if digest == r.digest {
		r.confirmations++
		return nil
	}
	d := configuration.RemoteBindings{ClusterID: cluster, ObservedAt: previous, Bindings: bindings}
	r.stored, r.digest = append(r.stored, d), digest
	return nil
}

func (r *recordedBindings) RemoteBindingsDigest(context.Context, string) (string, time.Time, error) {
	return r.digest, time.Unix(1700000000, 0), nil
}

type staticBindings struct {
	d contracts.AccessBindingDelivery
}

func (s staticBindings) AccessBindingDelivery(context.Context) (contracts.AccessBindingDelivery, error) {
	return s.d, nil
}

// ADR-329: the federation stores a delivery under the cluster its token
// was attributed to, never the hub cluster's, validating every spec.
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
	services := federationServices{ids: ids, bindings: &federationBindings{decoder, store}}
	run := func(lineageCluster string) (connectorlifecycle.HubFrame, error) {
		h, err := connectorlifecycle.NewHandler(clusterTokens{lineageCluster, root, "10000000-0000-4000-8000-000000000004", inst}, services, 2)
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
		client, err := connectorlifecycle.NewClient(server.URL, roots, func() ([]byte, error) { return []byte("synthetic"), nil })
		if err != nil {
			t.Fatal(err)
		}
		// The process binding claims the lineage's cluster, as the real one must.
		process := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: inst, ClusterID: lineageCluster, IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}, PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
		spec, _ := json.Marshal(map[string]any{"reason": "synthetic fixture", "effect": "Allow", "roles": []string{"evidence-reader"}, "subjects": []any{map[string]string{"kind": "Group", "issuer": "https://id.example.test", "id": "team-a"}}})
		delivery := contracts.AccessBindingDelivery{ResourceVersion: "9", Items: []contracts.DeliveredAccessBinding{{Namespace: "payments", NamespaceUID: "payments-uid", Name: "readers", UID: "b-1", ResourceVersion: "3", Generation: 1, Spec: spec}}}
		return client.Run(context.Background(), connectorlifecycle.Opening{Purpose: connectorlifecycle.PurposeAccessBindings, OperationID: "10000000-0000-4000-8000-000000000008", Process: process}, deliveringLocal{staticBindings{delivery}})
	}
	result, err := run(remote)
	if err != nil || result.Kind != "result" || len(store.stored) != 1 {
		t.Fatal("delivery", result.Kind, err, len(store.stored))
	}
	d := store.stored[0]
	if d.ClusterID != remote || len(d.Bindings) != 1 || d.Bindings[0].Scope.ClusterID != remote || d.Bindings[0].Invalid || !d.ObservedAt.Equal(time.Unix(1700000000, 0)) || !d.Valid() {
		t.Fatalf("stored %+v", d)
	}
	// An unchanged LIST matches the stored digest: nothing is stored again.
	if result, err = run(remote); err != nil || result.Kind != "result" || len(store.stored) != 1 {
		t.Fatal("unchanged delivery stored again", result.Kind, err, len(store.stored))
	}
	if store.confirmations != 1 {
		t.Fatal("unchanged delivery was not confirmed")
	}
	store.digest = ""
	// The hub cluster's own connector is observed directly, never delivered.
	if result, err = run(hub); err != nil || result.Kind != "failure" || len(store.stored) != 1 {
		t.Fatal("hub cluster delivery accepted", result.Kind, err)
	}
}
