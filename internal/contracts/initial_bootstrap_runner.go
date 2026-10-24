package contracts

import "io"

const InitialBootstrapRunnerInputFormat = "asservat-bootstrap-runner/v1"

// Stable references only, never credential bodies or generated installation
// pins. Stored alongside public input in the chart's immutable ConfigMap.
type InitialBootstrapRunnerInput struct {
	Format           string `json:"format"`
	ProducerSecret   string `json:"producerSecret"`
	SchemaSecret     string `json:"schemaSecret"`
	RetirementSecret string `json:"retirementSecret"`
	RegistrySecret   string `json:"registrySecret,omitempty"`
	// The full public continuation digest selects its immutable ConfigMap.
	// Omission keeps the original bootstrap-only runner bytes and layout.
	ContinuationDigest string `json:"continuationDigest,omitempty"`
}

func DecodeInitialBootstrapRunnerInput(r io.Reader) (InitialBootstrapRunnerInput, error) {
	return decodeClosedRPC[InitialBootstrapRunnerInput](r, 2048)
}
