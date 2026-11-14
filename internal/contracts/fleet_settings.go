package contracts

// FleetSettings is the Helm-rendered fleet.json of the fleet ConfigMap. It
// holds only chart values: the reader takes the installation ID and issuer
// epoch from the generated IDs (InstallationIDs).
type FleetSettings struct {
	SchemaVersion       string            `json:"schemaVersion"`
	Revision            int64             `json:"revision"`
	Issuer              string            `json:"issuer"`
	Suspended           bool              `json:"suspended"`
	Clients             []string          `json:"clients"`
	Subjects            []IdentitySubject `json:"subjects"`
	Groups              []string          `json:"groups"`
	DeliveryProfiles    []string          `json:"deliveryProfiles"`
	MaxActiveBootstraps int               `json:"maxActiveBootstraps"`
	MaxBootstrapHistory int               `json:"maxBootstrapHistory"`
	MaxClusters         int               `json:"maxClusters"`
}
