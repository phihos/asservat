package live

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

const (
	capacityInstallation = "11111111-2222-4333-8444-555555555555"
	capacityCluster      = "22222222-3333-4444-8555-666666666666"
)

type capacityFixture struct {
	now         time.Time
	caller      identity.Identity
	admin       fleet.Administration
	recovery    artifact.RecoveryProof
	snapshot    collector.LiveRuntimeSnapshot
	reads       int
	resolved    int
	change      func(*identity.Identity)
	targetErr   error
	viewers     int
	viewerFresh time.Time
	viewerErr   error
	viewerReads int
}

func (f *capacityFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	f.resolved++
	caller := f.caller
	if f.resolved > 1 && f.change != nil {
		f.change(&caller)
	}
	return caller, nil
}
func (f *capacityFixture) FleetAdministration(context.Context) (fleet.Administration, error) {
	return f.admin, nil
}
func (f *capacityFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *capacityFixture) ReadLiveRuntime(context.Context, collector.LiveRuntimeRequest) (collector.LiveRuntimeSnapshot, error) {
	f.reads++
	return f.snapshot, f.targetErr
}
func (f *capacityFixture) ReadLiveViewers(context.Context, string, string) (int, time.Time, error) {
	f.viewerReads++
	return f.viewers, f.viewerFresh, f.viewerErr
}

func newCapacityFixture() (*capacityFixture, CapacityReader) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	revision := identity.Revision{UID: "revision", Generation: 1, Digest: artifact.Digest{1}}
	f := &capacityFixture{now: now, viewers: 3, viewerFresh: now.Add(5 * time.Second)}
	f.caller = identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: revision, VerifiedAt: now, ValidUntil: now.Add(30 * time.Second)}
	f.admin = fleet.Administration{InstallationID: capacityInstallation, IssuerEpoch: capacityInstallation, Issuer: f.caller.Principal.Issuer, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []string{"console"}, Groups: []string{"platform-admins"}, DeliveryProfiles: []string{"kv"}, MaxActiveBootstraps: 1, MaxBootstrapHistory: 1, MaxClusters: 1}
	f.recovery = artifact.RecoveryProof{InstallationID: capacityInstallation, IssuerEpoch: capacityInstallation, Revision: revision, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	f.snapshot = collector.LiveRuntimeSnapshot{ClusterID: capacityCluster, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Nodes: 1, RatesComplete: true, Live: &collector.LiveActivity{Cohorts: 1, ScanEvents: 2}}
	return f, CapacityReader{InstallationID: capacityInstallation, Administration: f, Recovery: f, Targets: f, Viewers: f, Clusters: []string{capacityCluster}, Now: func() time.Time { return f.now }}
}

func TestCapacityReaderAuthorizesOneClusterAndRechecksCaller(t *testing.T) {
	f, service := newCapacityFixture()
	got, until, err := service.Read(context.Background(), f, capacityCluster)
	if err != nil || got.ActiveViewers != 3 || got.Live.ScanEvents != 2 || !until.Equal(f.snapshot.FreshUntil) || f.reads != 1 || f.viewerReads != 1 || f.resolved != 2 {
		t.Fatal(got, until, err, f.reads, f.viewerReads, f.resolved)
	}
	f, service = newCapacityFixture()
	f.viewerErr = v.ErrUnavailable
	if _, _, err = service.Read(context.Background(), f, capacityCluster); !errors.Is(err, identity.ErrUnavailable) || f.resolved != 1 {
		t.Fatal("viewer outage returned data or skipped its bound", err, f.resolved)
	}
	f, service = newCapacityFixture()
	f.caller.Groups = nil
	if _, _, err = service.Read(context.Background(), f, capacityCluster); !errors.Is(err, identity.ErrDenied) || f.reads != 0 {
		t.Fatal("non-operator reached regional read", err, f.reads)
	}
	f, service = newCapacityFixture()
	f.change = func(caller *identity.Identity) { caller.Groups = nil }
	if _, _, err = service.Read(context.Background(), f, capacityCluster); !errors.Is(err, identity.ErrDenied) || f.reads != 1 {
		t.Fatal("caller role loss returned data", err, f.reads)
	}
	f, service = newCapacityFixture()
	f.snapshot.ClusterID = capacityInstallation
	if _, _, err = service.Read(context.Background(), f, capacityCluster); !errors.Is(err, identity.ErrUnavailable) {
		t.Fatal("wrong cluster accepted", err)
	}
	f, service = newCapacityFixture()
	if _, _, err = service.Read(context.Background(), f, "not-a-cluster"); !errors.Is(err, v.ErrInvalid) || f.reads != 0 {
		t.Fatal("invalid cluster reached regional read", err, f.reads)
	}
	f, service = newCapacityFixture()
	if _, _, err = service.Read(context.Background(), f, capacityInstallation); !errors.Is(err, ErrClusterUnknown) || f.reads != 0 {
		t.Fatal("unknown cluster reached regional read", err, f.reads)
	}
}
