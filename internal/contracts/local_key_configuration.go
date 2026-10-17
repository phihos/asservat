package contracts

// LocalKeyConfiguration is a protected ConfigMap payload, not a public grant.
// It references immutable Secret bytes; it never contains key material.
type LocalKeyConfiguration struct {
	Format           string                  `json:"format"`
	InstallationID   string                  `json:"installationID"`
	Purpose          string                  `json:"purpose"`
	KeyID            string                  `json:"keyID"`
	RecoveryEpoch    string                  `json:"recoveryEpoch"`
	Revision         int64                   `json:"revision"`
	Suspended        bool                    `json:"suspended"`
	Secret           LocalKeySecretReference `json:"secret"`
	SigningPublicKey []byte                  `json:"signingPublicKey,omitempty"`
}
type LocalKeySecretReference struct {
	Name   string `json:"name"`
	UID    string `json:"uid"`
	SHA256 string `json:"sha256"`
}
