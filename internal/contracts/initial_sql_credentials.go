package contracts

import (
	"io"
	"time"
)

const InitialSQLCredentialsFormat = "asservat-initial-sql-credentials/v1"

// Private immutable Secret payload. Never put this in a ConfigMap, audit,
// public API, arguments, or log. PlanDigest binds the full installer inputs.
type InitialSQLCredentialState struct {
	Format         string             `json:"format"`
	InstallationID string             `json:"installationID"`
	PlanDigest     string             `json:"planDigest"`
	NotBefore      time.Time          `json:"notBefore"`
	NotAfter       time.Time          `json:"notAfter"`
	Preparation    OwnerSQLCredential `json:"preparation"`
	Audit          OwnerSQLCredential `json:"audit"`
	Activation     OwnerSQLCredential `json:"activation"`
}

func DecodeInitialSQLCredentialState(r io.Reader) (InitialSQLCredentialState, error) {
	return decodeClosedRPC[InitialSQLCredentialState](r, 4096)
}

func (InitialSQLCredentialState) String() string   { return "protected initial SQL credential state" }
func (InitialSQLCredentialState) GoString() string { return "protected initial SQL credential state" }
