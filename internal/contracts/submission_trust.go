package contracts

import "time"

type SubmissionTrust struct {
	SchemaVersion  string          `json:"schemaVersion"`
	Revision       int64           `json:"revision"`
	RootID         string          `json:"rootID"`
	InstallationID string          `json:"installationID"`
	IssuerEpoch    string          `json:"issuerEpoch"`
	Keys           []SubmissionKey `json:"keys"`
}
type SubmissionKey struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"publicKey"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}
