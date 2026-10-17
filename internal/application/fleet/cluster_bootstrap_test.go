package fleet

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

func bootstrapEnvelopeFixture(now time.Time) value.BootstrapEnvelope {
	return value.BootstrapEnvelope{BootstrapID: "10000000-0000-4000-8000-000000000011",
		Binding:         value.PeerBinding{InstallationID: "10000000-0000-4000-8000-000000000003", ClusterID: "10000000-0000-4000-8000-000000000004", IssuerEpoch: "10000000-0000-4000-8000-000000000012", PeerID: "10000000-0000-4000-8000-000000000002", Role: value.ConnectorPeer},
		DeliveryProfile: "synthetic", RequestDigest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(5 * time.Minute), Secret: "synthetic-bootstrap-secret"}
}

// ADR-193: the pending generation-1 key signs the bootstrap over the TLS
// exporter; another exporter, key or field does not verify.
func TestClusterBootstrapRequestIsExporterBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := bootstrapEnvelopeFixture(now)
	b := e.Binding
	r := value.ClusterBootstrapRequest{InstallationID: b.InstallationID, BootstrapID: e.BootstrapID, RootID: "10000000-0000-4000-8000-000000000001", ClusterID: b.ClusterID, PeerID: b.PeerID, IssuerEpoch: b.IssuerEpoch,
		KeyDigest: artifact.Digest{2}, SecretDigest: artifact.Digest{3}, RequestedAt: now}
	if !r.Valid() || !r.Matches(e) || !e.Valid() {
		t.Fatal("valid bootstrap refused")
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	key := ed25519.NewKeyFromSeed(seed)
	exporter := make([]byte, 32)
	signature, err := SignClusterBootstrapRequest(key, r, exporter)
	if err != nil || !VerifyClusterBootstrapRequest(key.Public().(ed25519.PublicKey), r, signature, exporter) {
		t.Fatal("bootstrap signature does not verify", err)
	}
	other := make([]byte, 32)
	other[0] = 1
	changed := r
	changed.PeerID = "10000000-0000-4000-8000-000000000099"
	if VerifyClusterBootstrapRequest(key.Public().(ed25519.PublicKey), r, signature, other) || VerifyClusterBootstrapRequest(key.Public().(ed25519.PublicKey), changed, signature, exporter) || changed.Matches(e) {
		t.Fatal("signature replayed on another connection or request")
	}
	long := e
	long.NotAfter = e.NotBefore.Add(6 * time.Minute)
	if long.Valid() {
		t.Fatal("bootstrap longer than five minutes")
	}
}

// ADR-193: generation 0 holds only the envelope and an optional pending seed;
// the rotator and signer refuse it, so only the bootstrap enrolls.
func TestClusterCredentialSecretGenerationZero(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	e := bootstrapEnvelopeFixture(now)
	seed := make([]byte, ed25519.SeedSize)
	zero := ClusterCredentialSecret{Generation: 0, Bootstrap: &e}
	pending := ClusterCredentialSecret{Generation: 0, Bootstrap: &e, PendingSeed: seed}
	if !zero.Valid() || !pending.Valid() {
		t.Fatal("generation 0 refused")
	}
	for name, s := range map[string]ClusterCredentialSecret{
		"seed at 0":           {Generation: 0, Bootstrap: &e, Seed: seed},
		"no envelope at 0":    {Generation: 0},
		"envelope at 1":       {Generation: 1, Seed: seed, RotatedAt: now, Bootstrap: &e},
		"short pending at 0":  {Generation: 0, Bootstrap: &e, PendingSeed: []byte{1}},
		"negative generation": {Generation: -1, Bootstrap: &e},
	} {
		if s.Valid() {
			t.Fatal("accepted:", name)
		}
	}
	profile := value.ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000001", PeerID: e.Binding.PeerID, InstallationID: e.Binding.InstallationID, ClusterID: e.Binding.ClusterID}
	rotator := ClusterCredentialRotator{Profile: profile, Policy: value.DefaultClusterCredentialPolicy(), Store: &secretMemory{state: zero}, Exchange: &hubMemory{}, Now: func() time.Time { return now }}
	if err := rotator.Reconcile(context.Background()); !errors.Is(err, value.ErrClusterBootstrapPending) {
		t.Fatal("rotation from generation 0", err)
	}
	if _, _, err := rotator.Signer(context.Background(), value.ClusterCredentialRequest{Operation: value.ClusterAdmission}); !errors.Is(err, value.ErrClusterBootstrapPending) {
		t.Fatal("admission signer from generation 0", err)
	}
}
