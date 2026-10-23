package privacy

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-200 revision (2026-10-23): an accepted retention source observation is
// current for 30 seconds after its original LIST/guard observation. A raw
// Kubernetes LIST snapshot keeps its five seconds; an invalidated (not Ready)
// source refuses at once.
func TestAcceptedRetentionSourceThirtySecondLifetime(t *testing.T) {
	sources, _, now := retentionObservationFixture()
	snapshot := sources[0]
	snapshot.FreshUntil = now.Add(RetentionSourceInterval)
	root := "22222222-2222-4222-8222-222222222222"
	s := AcceptedSource{RootID: root, Epoch: root, Snapshot: snapshot, Acceptance: identity.Revision{UID: root, Generation: 1, Digest: artifact.Digest{9}}, ProtectionDigest: artifact.Digest{8}, Ready: true, ObservedAt: now, FreshUntil: snapshot.FreshUntil}
	if RetentionSourceInterval != 30*time.Second || !s.Valid(now.Add(29*time.Second)) || s.Valid(now.Add(30*time.Second)) {
		t.Fatal("accepted source is not current for exactly 30 seconds")
	}
	if snapshot.Valid(now) {
		t.Fatal("raw LIST snapshot accepted a 30-second interval")
	}
	overlong := s
	overlong.FreshUntil = overlong.FreshUntil.Add(time.Nanosecond)
	invalidated := s
	invalidated.Ready = false
	if overlong.Valid(now) || invalidated.Valid(now) {
		t.Fatal("overlong or invalidated source accepted")
	}
	// Matching accepts accepted-source snapshots for their 30 seconds.
	_, f, _ := retentionObservationFixture()
	f.ObservedAt, f.FreshUntil = now.Add(20*time.Second), now.Add(25*time.Second)
	if _, until, err := MatchPolicies([]PolicySnapshot{snapshot}, f, now.Add(20*time.Second)); err != nil || !until.Equal(f.FreshUntil) {
		t.Fatal("thirty-second source snapshot refused", err)
	}
}
