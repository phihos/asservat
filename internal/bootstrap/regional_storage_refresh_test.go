package bootstrap

import (
	"context"
	"crypto/x509"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

type rotatingSettingsHub struct {
	settingsHub
	current atomic.Pointer[connectorlifecycle.Settings]
}

func (h *rotatingSettingsHub) Settings(context.Context, fleet.ConnectorCluster) (connectorlifecycle.Settings, error) {
	return *h.current.Load(), nil
}

func TestRegionalStorageRefreshUsesExistingSigners(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	o := connectorTestOffer(t, [][]byte{f.ca.Raw})
	credential := func(id string) contracts.OwnerStorageCredential {
		return contracts.OwnerStorageCredential{AccessKeyID: id, SecretAccessKey: "synthetic-" + id}
	}
	first := connectorlifecycle.Settings{ClusterID: connectorTestID("02"), PeerID: connectorTestID("05"), Offer: o, Evidence: credential("old-evidence"), History: credential("old-history")}
	hub := &rotatingSettingsHub{}
	hub.clusterTokens = clusterTokens{first.ClusterID, o.PermissionRootID, first.PeerID, o.InstallationID}
	hub.current.Store(&first)
	handler, err := connectorlifecycle.NewHandler(hub, hub, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := connectorlifecycle.NewClient(server.URL, roots, func() ([]byte, error) { return []byte("synthetic"), nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	c, err := readHubSettings(t.Context(), client, connectorTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	r := regionalContext{c: c, rootID: c.rootID(), owners: &RegionalLifecycle{Client: client}}
	r.storageKeys.Store(&regionalStorageKeys{c.evidence, c.history})
	evidence, history := r.storageCredentials(false), r.storageCredentials(true)
	check := func(want connectorlifecycle.Settings) {
		t.Helper()
		e, err := evidence.Retrieve(t.Context())
		if err != nil || e.AccessKeyID != want.Evidence.AccessKeyID || e.SecretAccessKey != want.Evidence.SecretAccessKey {
			t.Fatal("wrong evidence signer", err)
		}
		h, err := history.Retrieve(t.Context())
		if err != nil || h.AccessKeyID != want.History.AccessKeyID || h.SecretAccessKey != want.History.SecretAccessKey {
			t.Fatal("wrong history signer", err)
		}
	}
	check(first)
	replacement := first
	replacement.Evidence, replacement.History = credential("new-evidence"), credential("new-history")
	hub.current.Store(&replacement)
	if err := r.refreshStorageKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	check(replacement)
	foreign := first
	store := *o.EvidenceStore
	store.Bucket = "other-store"
	foreign.Offer.EvidenceStore = &store
	hub.current.Store(&foreign)
	if err := r.refreshStorageKeys(t.Context()); err == nil {
		t.Fatal("accepted credentials for another bucket")
	}
	check(replacement)
}
