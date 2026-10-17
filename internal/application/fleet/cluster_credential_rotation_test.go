package fleet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type secretMemory struct {
	state    ClusterCredentialSecret
	version  int
	failNext bool
}

func (m *secretMemory) ReadClusterCredential(context.Context) (ClusterCredentialSecret, string, error) {
	return m.state, string(rune('0' + m.version)), nil
}
func (m *secretMemory) WriteClusterCredential(_ context.Context, version string, next ClusterCredentialSecret) (string, error) {
	if m.failNext {
		m.failNext = false
		return "", errors.New("write lost")
	}
	if version != string(rune('0'+m.version)) {
		return "", errors.New("conflict")
	}
	m.state, m.version = next, m.version+1
	return string(rune('0' + m.version)), nil
}

// Exchanges through the real verifier against the in-memory hub store, with a
// fresh exporter per call like a new TLS connection. loseReply drops the reply
// after the hub committed, modelling an uncertain response.
type hubMemory struct {
	verifier  ClusterCredentialVerifier
	store     *clusterMemoryStore
	loseReply bool
	calls     int
}

func (h *hubMemory) ExchangeClusterCredential(ctx context.Context, r value.ClusterCredentialRequest, sign func([]byte) ([]byte, error)) (int64, error) {
	h.calls++
	exporter := make([]byte, 32)
	exporter[0] = byte(h.calls)
	signature, err := sign(exporter)
	if err != nil {
		return 0, err
	}
	p, err := h.verifier.Present(ctx, r, signature, exporter)
	if err != nil {
		return 0, err
	}
	if h.loseReply {
		h.loseReply = false
		return 0, errors.New("reply lost")
	}
	return p.Generation, nil
}

func TestClusterCredentialRotatorPersistsPendingAndRecovers(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	profile := value.ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000001", PeerID: "10000000-0000-4000-8000-000000000002", InstallationID: "10000000-0000-4000-8000-000000000003", ClusterID: "10000000-0000-4000-8000-000000000004"}
	store := &clusterMemoryStore{lineage: value.ClusterCredentialLineage{Profile: profile, ID: "10000000-0000-4000-8000-000000000005", Policy: value.DefaultClusterCredentialPolicy(), Current: 1}, creds: map[int64]*value.ClusterCredential{1: {Generation: 1, PublicKey: public, IssuedAt: now.Add(-time.Hour), ValidUntil: now.Add(7 * 24 * time.Hour)}}, now: now}
	hub := &hubMemory{verifier: ClusterCredentialVerifier{Store: store}, store: store}
	secret := &secretMemory{state: ClusterCredentialSecret{Generation: 1, Seed: seed, RotatedAt: now.Add(-time.Hour)}}
	clock := now
	rotator := ClusterCredentialRotator{Profile: profile, Policy: value.DefaultClusterCredentialPolicy(), Store: secret, Exchange: hub, Now: func() time.Time { return clock }}
	if err := rotator.Reconcile(context.Background()); err != nil || hub.calls != 0 || secret.state.PendingSeed != nil {
		t.Fatal("rotated before due", err)
	}
	clock = now.Add(25 * time.Hour)
	store.now = clock
	hub.loseReply = true // the hub commits generation 2, the reply is lost
	if err := rotator.Reconcile(context.Background()); err == nil || secret.state.PendingSeed == nil || secret.state.Generation != 1 || store.lineage.Current != 2 {
		t.Fatal("uncertain rotation did not keep the persisted pending key", err)
	}
	pending := secret.state.PendingSeed
	// Signing admissions with the superseded key is refused locally while pending.
	admission := value.ClusterCredentialRequest{Operation: value.ClusterAdmission, Profile: profile, Generation: 1, PodUID: "10000000-0000-4000-8000-000000000010", ProcessEpoch: "10000000-0000-4000-8000-000000000011", ClientKey: [32]byte{1}, ServerKey: [32]byte{2}, RequestedAt: clock}
	if _, _, err := rotator.Signer(context.Background(), admission); err == nil {
		t.Fatal("superseded key offered for admission")
	}
	// The process crashed and returns hours later: the exact replay completes.
	clock = clock.Add(6 * time.Hour)
	store.now = clock
	secret.failNext = false
	if err := rotator.Reconcile(context.Background()); err != nil || secret.state.Generation != 2 || secret.state.PendingSeed != nil || string(secret.state.Seed) != string(pending) {
		t.Fatal("exact replay did not finish the rotation", err, secret.state.Generation)
	}
	admission.Generation, admission.RequestedAt = 0, clock // the signer supplies the generation
	admission, sign, err := rotator.Signer(context.Background(), admission)
	if err != nil || admission.Generation != 2 {
		t.Fatal(err)
	}
	if g, err := hub.ExchangeClusterCredential(context.Background(), admission, sign); err != nil || g != 2 {
		t.Fatal("successor admission", g, err)
	}
	// When the pending key cannot be persisted, no rotation request is sent.
	clock = clock.Add(25 * time.Hour)
	store.now = clock
	secret.failNext = true // the pending write itself fails: no request is sent
	calls := hub.calls
	if err := rotator.Reconcile(context.Background()); err == nil || hub.calls != calls || secret.state.PendingSeed != nil {
		t.Fatal("rotation sent without a persisted pending key", err)
	}
	store.lineage.Fenced = "revoked"
	if err := rotator.Reconcile(context.Background()); !errors.Is(err, value.ErrClusterCredentialFenced) {
		t.Fatal("fence not surfaced", err)
	}
}
