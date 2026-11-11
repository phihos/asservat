package contracts

import "io"

const SmallServicesFormat = "asservat-small-services/v1"
const SmallServicesMaxBytes = 384 << 10

// SmallServicesPreparation contains public installation choices only. It is
// consumed by one finite hook before provider workloads start; it is neither
// an installation witness nor recovery or evidence authority.
type SmallServicesPreparation struct {
	Format      string                        `json:"format"`
	Namespace   string                        `json:"namespace"`
	Name        string                        `json:"name"`
	Kubernetes  InitialBootstrapEndpointInput `json:"kubernetes"`
	Postgres    bool                          `json:"postgres"`
	Keycloak    *SmallKeycloakSettings        `json:"keycloak,omitempty"`
	ObjectStore *SmallSeaweedPlan             `json:"objectStore,omitempty"`
	// Its password and roots remain separate selected operator Secret mounts.
	KeycloakExternalDatabase bool `json:"keycloakExternalDatabase,omitempty"`
}

type SmallKeycloakDatabase struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
}

func DecodeSmallServicesPreparation(r io.Reader) (SmallServicesPreparation, error) {
	return decodeClosedRPC[SmallServicesPreparation](r, SmallServicesMaxBytes)
}

func DecodeSmallKeycloakSettings(r io.Reader) (SmallKeycloakSettings, error) {
	return decodeClosedRPC[SmallKeycloakSettings](r, SmallServicesMaxBytes)
}
