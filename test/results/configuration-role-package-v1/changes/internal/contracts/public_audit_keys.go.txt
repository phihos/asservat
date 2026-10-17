package contracts

import "io"

const PublicAuditKeysFormat = "asservat-public-audit-keys/v1"
const PublicAuditKeysFile = "public-audit-keys.json"
const CaptureAccountKeyFormat = "asservat-capture-account-key/v1"
const CaptureAccountKeyFile = "capture-account-key.json"
const PublicAuditKeysMaxBytes = 2048

// Installation control secrets, not artifact wrapping keys. Versions and seeds
// are generated once before the protected role root's first CREATE. They never
// enter SQL, audit records or safe diagnostics. Ordinary restart is read-only.
type PublicAuditKeyMaterial struct {
	InputVersion   string `json:"inputVersion"`
	AccountVersion string `json:"accountVersion"`
	InputKey       []byte `json:"inputKey"`
	AccountKey     []byte `json:"accountKey"`
}

type PublicAuditKeys struct {
	Format         string                 `json:"format"`
	InstallationID string                 `json:"installationID"`
	RootUID        string                 `json:"rootUID"`
	SetupID        string                 `json:"setupID"`
	Material       PublicAuditKeyMaterial `json:"material"`
}

// The capacity compartment receives only this projection. It cannot calculate
// public input/output MACs and receives no public SQL/session credentials.
type CaptureAccountKey struct {
	Format         string `json:"format"`
	InstallationID string `json:"installationID"`
	RootUID        string `json:"rootUID"`
	SetupID        string `json:"setupID"`
	Version        string `json:"version"`
	Key            []byte `json:"key"`
}

func DecodePublicAuditKeys(r io.Reader) (PublicAuditKeys, error) {
	return decodeClosedRPC[PublicAuditKeys](r, PublicAuditKeysMaxBytes)
}
func DecodeCaptureAccountKey(r io.Reader) (CaptureAccountKey, error) {
	return decodeClosedRPC[CaptureAccountKey](r, PublicAuditKeysMaxBytes)
}
func (PublicAuditKeyMaterial) String() string   { return "protected public audit HMAC material" }
func (PublicAuditKeyMaterial) GoString() string { return "protected public audit HMAC material" }
func (PublicAuditKeys) String() string          { return "protected public audit HMAC projection" }
func (PublicAuditKeys) GoString() string        { return "protected public audit HMAC projection" }
func (CaptureAccountKey) String() string        { return "protected capture account HMAC projection" }
func (CaptureAccountKey) GoString() string      { return "protected capture account HMAC projection" }
