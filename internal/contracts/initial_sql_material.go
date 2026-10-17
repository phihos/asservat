package contracts

import "io"

const InitialSQLMaterialFormat = "asservat-initial-sql-material/v1"

// This immutable private bootstrap input contains unissued random password
// material. It has no role, validity interval or provider-issued credential.
// Never put it or a payload hash in the public preparation root or logs.
type InitialSQLMaterial struct {
	Format              string `json:"format"`
	InstallationID      string `json:"installationID"`
	RequestID           string `json:"requestID"`
	PreparationPassword string `json:"preparationPassword"`
	AuditPassword       string `json:"auditPassword"`
	ActivationPassword  string `json:"activationPassword"`
}

func DecodeInitialSQLMaterial(r io.Reader) (InitialSQLMaterial, error) {
	return decodeClosedRPC[InitialSQLMaterial](r, 2048)
}
func (InitialSQLMaterial) String() string   { return "protected initial SQL material" }
func (InitialSQLMaterial) GoString() string { return "protected initial SQL material" }
