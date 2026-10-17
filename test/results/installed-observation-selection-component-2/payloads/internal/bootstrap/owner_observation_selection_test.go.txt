package bootstrap

import (
	"context"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerObservationSelectionAloneCannotActivateV2Runtime(t *testing.T) {
	in, dir, config := ownerInputFixture(t)
	config.Observation = &contracts.OwnerObservationBootstrap{
		Format:           contracts.OwnerObservationFormat,
		TemplateDigest:   strings.Repeat("1", 64),
		ImageDigest:      strings.Repeat("2", 64),
		ProtectionDigest: strings.Repeat("3", 64),
		Activation:       ownerObservationTestActivation(config),
		Peers: []contracts.OwnerObservationPeer{{
			InstallationID: runtimeID, ClusterID: runtimeID,
			IssuerEpoch: runtimeID, PeerID: runtimeID, Roots: config.Kubernetes.Roots,
		}},
	}
	writeOwnerJSON(t, dir, "deployment.json", config)
	legacy, err := readOwnerInputs(context.Background(), in.files)
	if err != nil || legacy.config.Observation == nil || legacy.config.Observation.Format != contracts.OwnerObservationFormat {
		t.Fatal("same complete legacy input must remain valid", err)
	}
	// Original v2 selection is future installation provenance. This component
	// does not publish a complete regional backend or activate a v2 listener.
	config.Observation.Format = contracts.OwnerObservationOperationFormat
	writeOwnerJSON(t, dir, "deployment.json", config)
	if _, err = readOwnerInputs(context.Background(), in.files); err == nil {
		t.Fatal("selection alone activated incomplete runtime composition")
	}
}
