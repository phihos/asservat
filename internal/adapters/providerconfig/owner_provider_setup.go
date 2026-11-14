package providerconfig

import (
	"encoding/json"
	"time"
)

type OwnerPKIRoleRecipe struct {
	Name string          `json:"name"`
	Role json.RawMessage `json:"role"`
}

// OwnerSetupRecipe adds provider setup to the unchanged authentication recipe.
// It is public automation input, not an admin write, current observation, CSR,
// private key, installer authority or permission to use any of these roles.
type OwnerSetupRecipe struct {
	Authentication             OwnerProviderRecipe   `json:"authentication"`
	AuthMount                  json.RawMessage       `json:"authMount"`
	AuthConfiguration          json.RawMessage       `json:"authConfiguration"`
	ReviewerCredentialRequired bool                  `json:"reviewerCredentialRequired"`
	TransitKey                 json.RawMessage       `json:"transitKey"`
	PKIRoles                   [2]OwnerPKIRoleRecipe `json:"pkiRoles"`
	InspectionPolicy           json.RawMessage       `json:"inspectionPolicy"`
}

// OwnerSetupCheck is a current configuration observation only. Private fields
// prevent constructing a successful check from a digest or caller timestamp.
type OwnerSetupCheck struct {
	binding           [32]byte
	observedAt, until time.Time
}
