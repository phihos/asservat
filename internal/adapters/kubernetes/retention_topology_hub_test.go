package kubernetes

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
)

func TestHubTopologyNamesOnlyTheHubRetentionSource(t *testing.T) {
	const cluster, root, ns = "10000000-0000-4000-8000-000000000001", "10000000-0000-4000-8000-000000000002", "10000000-0000-4000-8000-000000000003"
	client := &PermissionClient{clusterID: cluster, control: configuration.NamespaceRef{Name: "hub", UID: ns}, now: time.Now}
	topologies, err := NewRetentionTopologies(client, root, []RetentionTopologyPin{})
	if err != nil || topologies.AddHubTopology(client, root) != nil {
		t.Fatal(err)
	}
	if topologies.AddHubTopology(client, root) == nil {
		t.Fatal("second hub topology accepted")
	}
	got, err := topologies.RetentionTopology(t.Context(), cluster)
	if err != nil || len(got.Sources) != 1 || !got.Sources[0].Hub || got.Sources[0].ControlNamespaceUID != ns || got.Sources[0].ProtectionDigest != artifact.Digest(contracts.RetentionSourceDigest(cluster, "hub")) || got.RootID != root {
		t.Fatal("hub topology", got, err)
	}
	if _, err = topologies.RetentionTopology(t.Context(), root); err == nil {
		t.Fatal("other target served")
	}
}
