package bootstrap

import (
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Each joined regional capacity cluster keeps its own profile: the handler
// indexes them by cluster under one root and refuses duplicates, another
// root, invalid profiles and an empty or oversized set.
func TestRegionalOperationClustersIndexEachCluster(t *testing.T) {
	pin := func(cluster, root string) value.ConnectorObservationPin {
		return value.ConnectorObservationPin{Profile: value.ConnectorCredentialProfile{RootID: root, Binding: value.PeerBinding{InstallationID: runtimeID, ClusterID: cluster, IssuerEpoch: runtimeID, PeerID: observationForwardID(503), Role: value.ConnectorPeer}, Revision: identity.Revision{UID: observationForwardID(504), Generation: 1, Digest: artifact.Digest{33}}, ProtectionDigest: artifact.Digest{34}, ServerName: "connector.example.invalid", Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: runtimeID, ServiceAccount: "connector", AccountUID: runtimeID, Deployment: "connector", DeploymentUID: runtimeID, ServingSlots: 2, RetainedProcesses: 8}, ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{1}}},
			Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}, TemplateDigest: artifact.Digest{35}, ImageDigest: artifact.Digest{36}, ProtectionDigest: artifact.Digest{37}}
	}
	registry := &framedRegionalFixture{}
	root, a, b := observationForwardID(600), observationForwardID(601), observationForwardID(602)
	got, err := regionalOperationClusters([]regionalOperationCluster{{pin(a, root), registry}, {pin(b, root), registry}})
	if err != nil || len(got) != 2 || got[a].pin.Profile.Binding.ClusterID != a || got[b].pin.Profile.Binding.ClusterID != b {
		t.Fatal("two clusters not indexed", err)
	}
	invalid := pin(b, root)
	invalid.TemplateDigest = artifact.Digest{}
	many := make([]regionalOperationCluster, 17)
	for i := range many {
		many[i] = regionalOperationCluster{pin(observationForwardID(700+i), root), registry}
	}
	for name, set := range map[string][]regionalOperationCluster{
		"empty":        nil,
		"duplicate":    {{pin(a, root), registry}, {pin(a, root), registry}},
		"other root":   {{pin(a, root), registry}, {pin(b, observationForwardID(603)), registry}},
		"invalid pin":  {{pin(a, root), registry}, {invalid, registry}},
		"no registry":  {{pin(a, root), nil}},
		"over ceiling": many,
	} {
		if _, err := regionalOperationClusters(set); err == nil {
			t.Fatal(name, "accepted")
		}
	}
}
