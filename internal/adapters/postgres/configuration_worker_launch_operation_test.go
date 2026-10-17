package postgres

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestConfigurationWorkerLaunchClaimsKeepOriginalRoleAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	original := contracts.ConfigurationRoleObservation{InstallationID: "installation", WorkloadDigest: "inert", GuardDigest: "guard", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	launch := &contracts.ConfigurationRuntimeLaunch{OperationID: "original", Sources: original, RunningDigest: "running", ProjectionUID: "projection", ClaimedAt: now, Until: now.Add(time.Second)}
	state := contracts.ConfigurationRuntimeRoleState{OperationID: "setup", Projection: &contracts.PublicRuntimeProjectionClaim{SecretUID: "projection"}, Launch: launch}
	for _, running := range []bool{false, true} {
		source := original
		if running {
			source.WorkloadDigest = "running"
		}
		source.ObservedAt = now.Add(2 * time.Second)
		source.FreshUntil = now.Add(4 * time.Second)
		snapshot := contracts.ConfigurationRuntimeRoleSnapshot{State: state, Sources: source}
		claims, ok := configurationWorkerLaunchClaimsSource(snapshot)
		if !ok || claims.WorkloadDigest != "inert" || !claims.ObservedAt.Equal(source.ObservedAt) || !claims.FreshUntil.Equal(source.FreshUntil) || !launch.Until.Equal(now.Add(time.Second)) {
			t.Fatal("launch comparison reset role/session dates or changed original workload")
		}
		for _, mutate := range []func(*contracts.ConfigurationRuntimeRoleSnapshot){
			func(v *contracts.ConfigurationRuntimeRoleSnapshot) { v.Sources.WorkloadDigest = "foreign" },
			func(v *contracts.ConfigurationRuntimeRoleSnapshot) { v.Sources.GuardDigest = "foreign" },
			func(v *contracts.ConfigurationRuntimeRoleSnapshot) { v.State.Launch = nil },
			func(v *contracts.ConfigurationRuntimeRoleSnapshot) { v.State.Projection = nil },
		} {
			bad := snapshot
			mutate(&bad)
			if _, ok := configurationWorkerLaunchClaimsSource(bad); ok {
				t.Fatal("foreign launch source accepted")
			}
		}
	}
}

func TestConfigurationWorkerLaunchFinalSQLStateOnlyAddsOriginalReceipt(t *testing.T) {
	original := contracts.ConfigurationRuntimeRoleState{OperationID: "setup", Launch: &contracts.ConfigurationRuntimeLaunch{OperationID: "launch", RunningDigest: "fixed"}}
	next := original
	claim := *original.Launch
	claim.Receipt = &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "20", ObservedAt: time.Now().UTC()}
	next.Launch = &claim
	if !configurationWorkerLaunchSameOriginal(original, next) {
		t.Fatal("original receipt rejected")
	}
	changed := next
	other := *next.Launch
	other.RunningDigest = "replacement"
	changed.Launch = &other
	if configurationWorkerLaunchSameOriginal(original, changed) {
		t.Fatal("final proof changed original launch")
	}
	changed = next
	other = *next.Launch
	receipt := *other.Receipt
	receipt.ResourceVersion = "21"
	other.Receipt = &receipt
	changed.Launch = &other
	if configurationWorkerLaunchSameOriginal(next, changed) {
		t.Fatal("final proof replaced prior receipt")
	}
}
