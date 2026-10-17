package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// In-memory store applying decisions like the SQL adapter, for exporter and
// signature binding only. Real PostgreSQL behavior is qualified separately.
type clusterMemoryStore struct {
	lineage value.ClusterCredentialLineage
	creds   map[int64]*value.ClusterCredential
	now     time.Time
}

func (s *clusterMemoryStore) Decide(_ context.Context, r value.ClusterCredentialRequest, decide ClusterCredentialDecider) (value.ClusterCredentialPresentation, error) {
	d, err := decide(s.lineage, s.creds[r.Generation], s.creds[s.lineage.Current], s.now)
	if err != nil {
		return value.ClusterCredentialPresentation{}, err
	}
	switch d.Kind {
	case value.ClusterRotate:
		s.creds[d.Supersede.Generation], s.creds[d.Next.Generation] = d.Supersede, d.Next
		s.lineage.Current = d.Next.Generation
	case value.ClusterFork:
		s.lineage.Fenced = "fork"
		return value.ClusterCredentialPresentation{}, value.ErrClusterCredentialFenced
	}
	return value.ClusterCredentialPresentation{Profile: s.lineage.Profile, LineageID: s.lineage.ID, Operation: r.Operation, Generation: s.lineage.Current, CheckedAt: s.now, ValidUntil: s.now.Add(5 * time.Second)}, nil
}

func TestClusterCredentialVerifierBindsSignatureAndConnection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	profile := value.ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000001", PeerID: "10000000-0000-4000-8000-000000000002", InstallationID: "10000000-0000-4000-8000-000000000003", ClusterID: "10000000-0000-4000-8000-000000000004"}
	store := &clusterMemoryStore{lineage: value.ClusterCredentialLineage{Profile: profile, ID: "10000000-0000-4000-8000-000000000005", Policy: value.DefaultClusterCredentialPolicy(), Current: 1}, creds: map[int64]*value.ClusterCredential{1: {Generation: 1, PublicKey: public, IssuedAt: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}}, now: now}
	v := ClusterCredentialVerifier{Store: store}
	exporter := make([]byte, 32)
	exporter[0] = 1
	r := value.ClusterCredentialRequest{Operation: value.ClusterAdmission, Profile: profile, Generation: 1, PodUID: "10000000-0000-4000-8000-000000000010", ProcessEpoch: "10000000-0000-4000-8000-000000000011", ClientKey: artifact.Digest{1}, ServerKey: artifact.Digest{2}, RequestedAt: now}
	sig, err := SignClusterCredentialRequest(private, r, exporter)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := v.Present(context.Background(), r, sig, exporter); err != nil || !p.Valid(now) {
		t.Fatal("signed admission", p, err)
	}
	other := make([]byte, 32)
	other[0] = 2
	if _, err = v.Present(context.Background(), r, sig, other); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("signature replayed on another connection", err)
	}
	changed := r
	changed.ProcessEpoch = "10000000-0000-4000-8000-000000000012"
	if _, err = v.Present(context.Background(), changed, sig, exporter); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("process substitution accepted", err)
	}
	_, impostor, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := SignClusterCredentialRequest(impostor, r, exporter)
	if _, err = v.Present(context.Background(), r, forged, exporter); !errors.Is(err, value.ErrClusterCredentialDenied) || store.lineage.Fenced != "" {
		t.Fatal("foreign key accepted or changed state", err)
	}
	unknown := r
	unknown.Generation = 7
	sig7, _ := SignClusterCredentialRequest(private, unknown, exporter)
	if _, err = v.Present(context.Background(), unknown, sig7, exporter); !errors.Is(err, value.ErrClusterCredentialDenied) {
		t.Fatal("unknown generation accepted", err)
	}
	next, _, _ := ed25519.GenerateKey(rand.Reader)
	rotate := value.ClusterCredentialRequest{Operation: value.ClusterRotation, Profile: profile, Generation: 1, NextKey: next, RequestedAt: now}
	rs, _ := SignClusterCredentialRequest(private, rotate, exporter)
	if p, err := v.Present(context.Background(), rotate, rs, exporter); err != nil || p.Generation != 2 || store.creds[1].Successor != ClusterKeyDigest(next) {
		t.Fatal("rotation through verifier", p, err)
	}
}
