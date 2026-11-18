package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	"github.com/google/uuid"
)

// clusterTokens stands in for the ServiceAccount verifier: it attributes
// every token to one registered cluster.
type clusterTokens struct{ cluster, root, peer, installation string }

func (p clusterTokens) VerifyConnector(context.Context, string) (value.ConnectorCluster, error) {
	return value.ConnectorCluster{RootID: p.root, PeerID: p.peer, InstallationID: p.installation, ClusterID: p.cluster}, nil
}

type recordedBindings struct {
	stored        []configuration.RemoteBindings
	revision      string
	digest        string
	confirmations int
}

func (r *recordedBindings) StoreRemoteBindings(_ context.Context, cluster string, previous string, digest string, bindings []configuration.Binding, unavailable bool) (string, error) {
	if previous != r.revision {
		return "", configuration.ErrChanged
	}
	r.revision = uuid.NewString()
	if digest == r.digest {
		r.confirmations++
		return r.revision, nil
	}
	d := configuration.RemoteBindings{ClusterID: cluster, ObservedAt: time.Unix(1700000000, 0), Bindings: bindings, Unavailable: unavailable}
	r.stored, r.digest = append(r.stored, d), digest
	return r.revision, nil
}

func (r *recordedBindings) RemoteBindingsDigest(context.Context, string) (string, string, error) {
	return r.digest, r.revision, nil
}

func (r *recordedBindings) BeginRemoteBindings(context.Context, string) (string, error) {
	return r.revision, nil
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
	store := &recordedBindings{revision: uuid.NewString()}
	ids := contracts.ServiceIDs{InstallationID: inst, ClusterID: hub, PermissionRootID: root}
	services := federationServices{ids: ids, bindings: &federationBindings{decoder, store}}
	clientFor := func(lineageCluster string) *RegionalLifecycle {
		h, err := connectorlifecycle.NewHandler(clusterTokens{lineageCluster, root, "10000000-0000-4000-8000-000000000004", inst}, services, 2)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(h)
		server.EnableHTTP2 = true
		server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		server.StartTLS()
		t.Cleanup(server.Close)
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		client, err := connectorlifecycle.NewClient(server.URL, roots, func() ([]byte, error) { return []byte("synthetic"), nil })
		if err != nil {
			t.Fatal(err)
		}
		// The process binding claims the lineage's cluster, as the real one must.
		process := value.ConnectorProcessIdentity{Binding: value.PeerBinding{InstallationID: inst, ClusterID: lineageCluster, IssuerEpoch: "10000000-0000-4000-8000-000000000003", PeerID: "10000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}, PodUID: "10000000-0000-4000-8000-000000000005", ProcessEpoch: "10000000-0000-4000-8000-000000000006"}
		return &RegionalLifecycle{Client: client, RootID: root, Process: process, Now: time.Now}
	}
	remoteClient := clientFor(remote)
	hubClient := clientFor(hub)
	list := func(legacyMixedDeny bool) contracts.AccessBindingDelivery {
		spec, _ := json.Marshal(map[string]any{"reason": "synthetic fixture", "effect": "Allow", "roles": []string{"evidence-reader"}, "subjects": []any{map[string]string{"kind": "Group", "issuer": "https://id.example.test", "id": "team-a"}}})
		delivery := contracts.AccessBindingDelivery{ResourceVersion: "9", Items: []contracts.DeliveredAccessBinding{{Namespace: "payments", NamespaceUID: "payments-uid", Name: "readers", UID: "b-1", ResourceVersion: "3", Generation: 1, Spec: spec}}}
		if legacyMixedDeny {
			spec, _ := json.Marshal(map[string]any{"reason": "synthetic", "effect": "Deny", "roles": []string{"evidence-reader"}, "subjects": []map[string]string{{"kind": "Group", "id": "team-a"}, {"kind": "Group", "id": strings.Repeat("x", 257)}}})
			delivery.Items = append(delivery.Items, contracts.DeliveredAccessBinding{Kind: configuration.ClusterAccessBindingKind, Name: "blocked", UID: "b-2", ResourceVersion: "4", Generation: 1, Spec: spec})
		}
		return delivery
	}
	run := func(client *RegionalLifecycle, legacyMixedDeny bool) error {
		revision, err := client.bindingRevision(t.Context())
		if err != nil {
			return err
		}
		_, err = client.deliverAccessBindings(t.Context(), revision, list(legacyMixedDeny))
		return err
	}
	if err := run(remoteClient, false); err != nil || len(store.stored) != 1 {
		t.Fatal("delivery", err, len(store.stored))
	}
	d := store.stored[0]
	if d.ClusterID != remote || len(d.Bindings) != 1 || d.Bindings[0].Scope.ClusterID != remote || d.Bindings[0].Invalid || !d.ObservedAt.Equal(time.Unix(1700000000, 0)) || !d.Valid() {
		t.Fatalf("stored %+v", d)
	}
	// An unchanged LIST matches the stored digest: nothing is stored again.
	if err = run(remoteClient, false); err != nil || len(store.stored) != 1 {
		t.Fatal("unchanged delivery stored again", err, len(store.stored))
	}
	if store.confirmations != 1 {
		t.Fatal("unchanged delivery was not confirmed")
	}
	if err = run(remoteClient, true); err != nil || len(store.stored) != 2 || !store.stored[1].Unavailable || len(store.stored[1].Bindings) != 0 {
		t.Fatal("legacy mixed-subject Deny left its overlapping Allow active", err)
	}
	if err = run(remoteClient, true); err != nil || len(store.stored) != 2 || store.confirmations != 2 {
		t.Fatal("unchanged unrepresentable Deny restored the Allow", err)
	}
	// Acquire both predecessors before sampling. Reverse publication order:
	// the delayed Allow cannot undo the newer deletion, even on an idle hub.
	first, err := remoteClient.bindingRevision(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stale := list(false)
	second, err := remoteClient.bindingRevision(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	deleted := contracts.AccessBindingDelivery{ResourceVersion: "10"}
	if _, err = remoteClient.deliverAccessBindings(t.Context(), second, deleted); err != nil {
		t.Fatal(err)
	}
	if _, err = remoteClient.deliverAccessBindings(t.Context(), first, stale); err == nil || store.digest != deleted.Digest() || len(store.stored[len(store.stored)-1].Bindings) != 0 {
		t.Fatal("delayed Allow replaced newer deletion", err)
	}
	current, err := remoteClient.bindingRevision(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	incomplete := list(false)
	incomplete.Items[0].NamespaceUID = ""
	if _, err = remoteClient.deliverAccessBindings(t.Context(), current, incomplete); err != nil || !store.stored[len(store.stored)-1].Unavailable {
		t.Fatal("incomplete replacement left the previous delivery usable", err)
	}
	// The hub cluster's own connector is observed directly, never delivered.
	if err = run(hubClient, false); err == nil || len(store.stored) != 4 {
		t.Fatal("hub cluster delivery accepted", err)
	}
}
