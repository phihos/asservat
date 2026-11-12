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
	// Fixed retained bundled-PostgreSQL source. Only the public CA and exact
	// phase credential keys are projected; provider material remains separate.
	PostgresSecret    string `json:"postgresSecret,omitempty"`
	KeycloakSecret    string `json:"keycloakSecret,omitempty"`
	ObjectStoreSecret string `json:"objectStoreSecret,omitempty"`
	// The full public continuation digest selects its immutable ConfigMap.
	// Omission keeps the original bootstrap-only runner bytes and layout.
	ContinuationDigest string `json:"continuationDigest,omitempty"`
}

func DecodeInitialBootstrapRunnerInput(r io.Reader) (InitialBootstrapRunnerInput, error) {
	return decodeClosedRPC[InitialBootstrapRunnerInput](r, 2048)
}
