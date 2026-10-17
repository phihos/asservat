package contracts

// InstallationWitness is private ConfigMap data, not a public operation API.
// Kubernetes UID/resourceVersion, immutable state and protection are verified
// separately. No field in this document confers activation authority.
type InstallationWitness struct {
	SchemaVersion    string                  `json:"schemaVersion"`
	InstallationID   string                  `json:"installationID"`
	IssuerEpoch      string                  `json:"issuerEpoch"`
	WriterAccountUID string                  `json:"writerAccountUID"`
	Claim            *InitialActivationClaim `json:"claim"`
}

type InitialActivationClaim struct {
	ID            string `json:"id"`
	DatabaseStart string `json:"databaseStart"`
	DatabaseOID   uint32 `json:"databaseOID"`
	SchemaVersion int64  `json:"databaseSchemaVersion"`
	SourceUID     string `json:"sourceUID"`
	SourceVersion int64  `json:"sourceGeneration"`
	SourceDigest  string `json:"sourceDigest"`
	PlanDigest    string `json:"planDigest"`
	NotBefore     string `json:"notBefore"`
	NotAfter      string `json:"notAfter"`
}
