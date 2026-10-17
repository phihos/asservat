package bootstrap

import (
	"context"
	"os"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInstalledCapacityRejectsRemoteEndpointFallback(t *testing.T) {
	for _, c := range []struct {
		name     string
		endpoint contracts.OwnerProviderEndpoint
	}{
		{"endpoint", contracts.OwnerProviderEndpoint{Endpoint: "https://regional.example.test"}},
		{"roots", contracts.OwnerProviderEndpoint{Roots: [][]byte{[]byte("foreign roots")}}},
		{"both", contracts.OwnerProviderEndpoint{Endpoint: "https://regional.example.test", Roots: [][]byte{[]byte("foreign roots")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if capacityClusterEndpoint(true, runtimeID, runtimeID, c.endpoint) {
				t.Fatal("installed profile accepted remote Kubernetes authority")
			}
		})
	}
	if !capacityClusterEndpoint(true, runtimeID, runtimeID, contracts.OwnerProviderEndpoint{}) {
		t.Fatal("installed local hop requires an unproduced remote endpoint")
	}
	if capacityClusterEndpoint(false, runtimeID, runtimeID, contracts.OwnerProviderEndpoint{}) {
		t.Fatal("legacy component endpoint validation weakened")
	}
	_, _, owner := ownerInputFixture(t)
	if !capacityClusterEndpoint(false, runtimeID, runtimeID, owner.Kubernetes) {
		t.Fatal("legacy component lost its hub cluster API")
	}
	if capacityClusterEndpoint(false, runtimeID, "10000000-0000-4000-8000-0000000000aa", owner.Kubernetes) {
		t.Fatal("legacy component read a workload cluster API directly (ADR-179)")
	}
}

func TestInstalledCapacityNeedsReceiptBeforeOpeningCredentials(t *testing.T) {
	files, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	// An empty mount is deliberate. No filename or ambient credentials can
	// select the installed path without its concrete current journal reader.
	if _, err = NewInstalledCapacityWorkerDeployment(context.Background(), files, files, contracts.HubWorkerDeployment{}, nil, contracts.CapacityRuntimeProjectionClaim{}); err == nil {
		t.Fatal("unreceipted installed worker opened")
	}
}

func TestCapacityObservationTokenUsesOnlyFixedKubeletFile(t *testing.T) {
	dir := t.TempDir()
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	if err = os.WriteFile(dir+"/kube-capacity-probe.token", []byte("synthetic-observer-token"), 0600); err != nil {
		t.Fatal(err)
	}
	reader := mountedCapacityObservationToken{inputs: &providerInputs{files: files}}
	if _, err = reader.ReadClusterObservationToken(context.Background()); err == nil {
		t.Fatal("observation token inferred from old component projection")
	}
	token := []byte("synthetic-purpose-token")
	if err = os.WriteFile(dir+"/"+contracts.HubWorkerClusterObservationTokenFile, token, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadClusterObservationToken(context.Background())
	if err != nil || string(got) != string(token) {
		t.Fatal("fixed token unavailable", err)
	}
	clear(got)
	// A later read observes the kubelet's new bytes; this wrapper holds no token
	// cache. Online audience/Pod verification remains the server's separate duty.
	rotated := []byte("synthetic-rotated-purpose-token")
	if err = os.WriteFile(dir+"/"+contracts.HubWorkerClusterObservationTokenFile, rotated, 0600); err != nil {
		t.Fatal(err)
	}
	got, err = reader.ReadClusterObservationToken(context.Background())
	if err != nil || string(got) != string(rotated) {
		t.Fatal("fixed token rotation not observed", err)
	}
	clear(got)
	canceled, end := context.WithCancel(context.Background())
	end()
	if _, err = reader.ReadClusterObservationToken(canceled); err == nil {
		t.Fatal("canceled token read accepted")
	}
}
