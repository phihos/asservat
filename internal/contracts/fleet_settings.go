package contracts

type FleetSettings struct {
	SchemaVersion       string            `json:"schemaVersion"`
	Revision            int64             `json:"revision"`
	InstallationID      string            `json:"installationID"`
	IssuerEpoch         string            `json:"issuerEpoch"`
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
