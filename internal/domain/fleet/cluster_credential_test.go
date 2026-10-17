package fleet

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

type clusterFixture struct {
	lineage ClusterCredentialLineage
	current ClusterCredential
	now     time.Time
}

func clusterTestKey(b byte) []byte {
	k := make([]byte, ClusterPublicKeyBytes)
	k[0] = b
	return k
}
func clusterTestDigest(k []byte) artifact.Digest { return sha256.Sum256(k) }

func newClusterFixture() *clusterFixture {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	profile := ClusterCredentialProfile{RootID: "10000000-0000-4000-8000-000000000001", PeerID: "10000000-0000-4000-8000-000000000002", InstallationID: "10000000-0000-4000-8000-000000000003", ClusterID: "10000000-0000-4000-8000-000000000004"}
	return &clusterFixture{
		lineage: ClusterCredentialLineage{Profile: profile, ID: "10000000-0000-4000-8000-000000000005", Policy: DefaultClusterCredentialPolicy(), Current: 1},
		current: ClusterCredential{Generation: 1, PublicKey: clusterTestKey(1), IssuedAt: now.Add(-time.Hour), ValidUntil: now.Add(DefaultClusterCredentialValidity - time.Hour)},
		now:     now,
	}
}

func (f *clusterFixture) admission() ClusterCredentialRequest {
	return ClusterCredentialRequest{Operation: ClusterAdmission, Profile: f.lineage.Profile, Generation: f.current.Generation, PodUID: "10000000-0000-4000-8000-000000000010", ProcessEpoch: "10000000-0000-4000-8000-000000000011", ClientKey: artifact.Digest{1}, ServerKey: artifact.Digest{2}, RequestedAt: f.now}
}

func TestClusterCredentialPolicyBounds(t *testing.T) {
	if !DefaultClusterCredentialPolicy().Valid() {
		t.Fatal("default policy invalid")
	}
	for _, p := range []ClusterCredentialPolicy{
		{Validity: 59 * time.Minute, Rotation: time.Minute},
		{Validity: 31 * 24 * time.Hour, Rotation: time.Hour},
		{Validity: 7 * 24 * time.Hour, Rotation: 3 * 24 * time.Hour}, // more than a third
		{Validity: time.Hour, Rotation: 30 * time.Second},
	} {
		if p.Valid() {
			t.Fatal("out-of-bounds policy accepted", p)
		}
	}
}

func TestClusterCredentialAdmissionDecisions(t *testing.T) {
	f := newClusterFixture()
	r := f.admission()
	d, err := DecideClusterCredential(f.lineage, &f.current, &f.current, r, true, artifact.Digest{}, f.now)
	if err != nil || d.Kind != ClusterAccept || !d.FirstUse {
		t.Fatal("current admission", d, err)
	}
	if _, err = DecideClusterCredential(f.lineage, &f.current, &f.current, r, false, artifact.Digest{}, f.now); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("unsigned admission accepted", err)
	}
	wrong := r
	wrong.Profile.ClusterID = "10000000-0000-4000-8000-000000000099"
	if _, err = DecideClusterCredential(f.lineage, &f.current, &f.current, wrong, true, artifact.Digest{}, f.now); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("another cluster's profile accepted", err)
	}
	if _, err = DecideClusterCredential(f.lineage, &f.current, &f.current, r, true, artifact.Digest{}, f.now.Add(ClusterCredentialRequestSkew+time.Second)); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("stale request time accepted", err)
	}
	expired := f.current
	expired.ValidUntil = f.now
	if _, err = DecideClusterCredential(f.lineage, &expired, &expired, r, true, artifact.Digest{}, f.now); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("expired credential accepted", err)
	}
	f.current.FirstUsed = f.now
	if d, err = DecideClusterCredential(f.lineage, &f.current, &f.current, r, true, artifact.Digest{}, f.now); err != nil || d.FirstUse {
		t.Fatal("first use recorded twice", d, err)
	}
	invalid := r
	invalid.ServerKey = invalid.ClientKey
	if _, err = DecideClusterCredential(f.lineage, &f.current, &f.current, invalid, true, artifact.Digest{}, f.now); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("identical client/server keys accepted", err)
	}
}

func TestClusterCredentialRotationReplayAndFork(t *testing.T) {
	f := newClusterFixture()
	next := clusterTestKey(2)
	rotate := ClusterCredentialRequest{Operation: ClusterRotation, Profile: f.lineage.Profile, Generation: 1, NextKey: next, RequestedAt: f.now}
	d, err := DecideClusterCredential(f.lineage, &f.current, &f.current, rotate, true, clusterTestDigest(next), f.now)
	if err != nil || d.Kind != ClusterRotate || d.Next.Generation != 2 || !d.Next.ValidUntil.Equal(f.now.Add(DefaultClusterCredentialValidity)) || d.Supersede.Successor != clusterTestDigest(next) {
		t.Fatal("rotation", d, err)
	}
	old, current := *d.Supersede, *d.Next
	lineage := f.lineage
	lineage.Current = 2
	retry := rotate
	retry.RequestedAt = f.now.Add(time.Minute)
	if d, err = DecideClusterCredential(lineage, &old, &current, retry, true, clusterTestDigest(next), retry.RequestedAt); err != nil || d.Kind != ClusterReplay {
		t.Fatal("exact replay", d, err)
	}
	// A connector down for hours after a lost acknowledgement can still finish.
	late := rotate
	late.RequestedAt = f.now.Add(6 * time.Hour)
	if d, err = DecideClusterCredential(lineage, &old, &current, late, true, clusterTestDigest(next), late.RequestedAt); err != nil || d.Kind != ClusterReplay {
		t.Fatal("late exact replay after a crash refused", d, err)
	}
	expired := current
	expired.ValidUntil = late.RequestedAt
	if d, _ = DecideClusterCredential(lineage, &old, &expired, late, true, clusterTestDigest(next), late.RequestedAt); d.Kind != ClusterFork {
		t.Fatal("replay after successor expiry not fenced", d)
	}
	used := current
	used.FirstUsed = f.now
	if d, _ = DecideClusterCredential(lineage, &old, &used, retry, true, clusterTestDigest(next), retry.RequestedAt); d.Kind != ClusterFork {
		t.Fatal("replay after successor use not fenced", d)
	}
	forked := retry
	forked.NextKey = clusterTestKey(3)
	if d, _ = DecideClusterCredential(lineage, &old, &current, forked, true, clusterTestDigest(forked.NextKey), retry.RequestedAt); d.Kind != ClusterFork {
		t.Fatal("divergent rotation not fenced", d)
	}
	admission := f.admission()
	if d, _ = DecideClusterCredential(lineage, &old, &current, admission, true, artifact.Digest{}, f.now); d.Kind != ClusterFork {
		t.Fatal("old-key admission not fenced", d)
	}
	if _, err = DecideClusterCredential(lineage, &old, &current, forked, false, clusterTestDigest(forked.NextKey), retry.RequestedAt); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("unsigned traffic changed state", err)
	}
	for _, fence := range []string{"fork", "revoked"} {
		fenced := lineage
		fenced.Fenced = fence
		a := admission
		a.Generation = 2
		if _, err = DecideClusterCredential(fenced, &current, &current, a, true, artifact.Digest{}, f.now); !errors.Is(err, ErrClusterCredentialFenced) {
			t.Fatal("fenced lineage admitted", fence, err)
		}
	}
	same := rotate
	same.NextKey = f.current.PublicKey
	if _, err = DecideClusterCredential(f.lineage, &f.current, &f.current, same, true, clusterTestDigest(same.NextKey), f.now); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("rotation to the same key accepted", err)
	}
	broken := old
	broken.SupersededAt, broken.Successor = time.Time{}, artifact.Digest{}
	if _, err = DecideClusterCredential(lineage, &broken, &current, retry, true, clusterTestDigest(next), retry.RequestedAt); !errors.Is(err, ErrClusterCredentialDenied) {
		t.Fatal("inconsistent history classified", err)
	}
}
