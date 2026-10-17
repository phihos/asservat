package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

type casSecret struct {
	state   fleetapp.ClusterCredentialSecret
	version int
}

func (s *casSecret) ReadClusterCredential(context.Context) (fleetapp.ClusterCredentialSecret, string, error) {
	c := s.state
	c.Seed, c.PendingSeed = bytes.Clone(c.Seed), bytes.Clone(c.PendingSeed)
	return c, strconv.Itoa(s.version), nil
}

func (s *casSecret) WriteClusterCredential(_ context.Context, version string, next fleetapp.ClusterCredentialSecret) (string, error) {
	if version != strconv.Itoa(s.version) || !next.Valid() {
		return "", value.ErrClusterCredentialDenied
	}
	next.Seed, next.PendingSeed = bytes.Clone(next.Seed), bytes.Clone(next.PendingSeed)
	s.state, s.version = next, s.version+1
	return strconv.Itoa(s.version), nil
}

// verifyingHub checks the opening as the federation handler does and records
// the key digest of every conversation.
type verifyingHub struct {
	store   *casSecret
	fail    error
	failure string
	digests []artifact.Digest
}

func (h *verifyingHub) Run(_ context.Context, open func([]byte) (connectorlifecycle.Opening, error), _ connectorlifecycle.Local) (connectorlifecycle.HubFrame, error) {
	exporter := bytes.Repeat([]byte{7}, 32)
	o, err := open(exporter)
	if err != nil || o.Purpose != connectorlifecycle.PurposeBootstrap || o.Bootstrap == nil {
		return connectorlifecycle.HubFrame{}, connectorlifecycle.ErrChannel
	}
	if h.store.state.PendingSeed == nil {
		panic("request before the pending key was stored")
	}
	b := o.Bootstrap
	key, digest, err := mtls.EnrollmentProof{}.BootstrapKey(b.CSRDER)
	secret, serr := mtls.BootstrapDigest(b.Request.InstallationID, b.Request.BootstrapID, b.Secret)
	if err != nil || serr != nil || digest != b.Request.KeyDigest || secret != b.Request.SecretDigest || !fleetapp.VerifyClusterBootstrapRequest(key, b.Request, b.Signature, exporter) {
		return connectorlifecycle.HubFrame{Kind: "failure", Failure: "unavailable"}, nil
	}
	h.digests = append(h.digests, digest)
	if h.fail != nil {
		return connectorlifecycle.HubFrame{}, h.fail
	}
	if h.failure != "" {
		return connectorlifecycle.HubFrame{Kind: "failure", Failure: h.failure}, nil
	}
	now := time.Now().UTC()
	return connectorlifecycle.HubFrame{Kind: "result", Bootstrap: &value.ClusterBootstrapResult{LineageID: "20000000-0000-4000-8000-000000000009", Generation: 1, KeyDigest: digest, IssuedAt: now, ValidUntil: now.Add(time.Hour)}}, nil
}

func regionalBootstrapFixture(t *testing.T) (regionalBootstrap, *casSecret, *verifyingHub) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	binding := value.PeerBinding{InstallationID: "20000000-0000-4000-8000-000000000001", ClusterID: "20000000-0000-4000-8000-000000000002", IssuerEpoch: "20000000-0000-4000-8000-000000000003", PeerID: "20000000-0000-4000-8000-000000000004", Role: value.ConnectorPeer}
	now := time.Now().UTC().Truncate(time.Microsecond)
	store := &casSecret{state: fleetapp.ClusterCredentialSecret{Bootstrap: &value.BootstrapEnvelope{BootstrapID: "20000000-0000-4000-8000-000000000005", Binding: binding, DeliveryProfile: "regional-installer",
		RequestDigest: artifact.Digest{1}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Minute), Secret: base64.RawURLEncoding.EncodeToString(raw)}}}
	hub := &verifyingHub{store: store}
	return regionalBootstrap{store: store, channel: hub, local: regionalLocal{}, binding: binding, root: "20000000-0000-4000-8000-000000000006", now: time.Now}, store, hub
}

// ADR-193 step 3e: the pending key is stored before any request, a lost reply
// resumes with the same key, and success promotes it to generation 1 while
// erasing the envelope.
func TestRegionalBootstrapPromotesThePendingKey(t *testing.T) {
	b, store, hub := regionalBootstrapFixture(t)
	hub.fail = connectorlifecycle.ErrChannel
	if err := b.Reconcile(context.Background()); !errors.Is(err, errRegionalChannel) || store.state.Generation != 0 || store.state.PendingSeed == nil {
		t.Fatal("lost reply", err)
	}
	pending := bytes.Clone(store.state.PendingSeed)
	hub.fail = nil
	if err := b.Reconcile(context.Background()); err != nil {
		t.Fatal("bootstrap", err)
	}
	s := store.state
	if s.Generation != 1 || s.Bootstrap != nil || s.PendingSeed != nil || !bytes.Equal(s.Seed, pending) || len(hub.digests) != 2 || hub.digests[0] != hub.digests[1] {
		t.Fatal("generation 1 not promoted from the stored pending key")
	}
	if err := b.Reconcile(context.Background()); err != nil || len(hub.digests) != 2 {
		t.Fatal("an enrolled Secret opened another bootstrap", err)
	}
}

func TestRegionalBootstrapRefusals(t *testing.T) {
	b, store, hub := regionalBootstrapFixture(t)
	hub.failure = "fenced"
	if err := b.Reconcile(context.Background()); !errors.Is(err, value.ErrClusterCredentialFenced) || store.state.Generation != 0 {
		t.Fatal("fenced bootstrap", err)
	}
	b, store, hub = regionalBootstrapFixture(t)
	store.state.Bootstrap.NotAfter = time.Now().Add(-time.Second)
	store.state.Bootstrap.NotBefore = store.state.Bootstrap.NotAfter.Add(-time.Minute)
	if err := b.Reconcile(context.Background()); !errors.Is(err, errRegionalBootstrapExpired) || len(hub.digests) != 0 || store.state.PendingSeed != nil {
		t.Fatal("expired bootstrap", err)
	}
	b, store, hub = regionalBootstrapFixture(t)
	b.binding.PeerID = "20000000-0000-4000-8000-0000000000ee"
	if err := b.Reconcile(context.Background()); !errors.Is(err, value.ErrDenied) || len(hub.digests) != 0 || store.state.PendingSeed != nil {
		t.Fatal("bootstrap for another slot", err)
	}
}
