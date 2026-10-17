package contracts

const KeyServiceFormat = "asservat-local-key-rpc/v1"
const KeyServicePath = "/internal/key-service/v1"
const KeyServiceMaxBody = 32768

type KeyScope struct {
	InstallationID string `json:"installationID"`
	Purpose        string `json:"purpose"`
	KeyID          string `json:"keyID"`
}
type SealedLocalKey struct {
	Reference  string `json:"reference"`
	Ciphertext string `json:"ciphertext"`
}
type KeyServiceRequest struct {
	Format      string          `json:"format"`
	Scope       KeyScope        `json:"scope"`
	AuthorityID string          `json:"authorityID"`
	Operation   string          `json:"operation"`
	Binding     []byte          `json:"binding,omitempty"`
	Input       []byte          `json:"input,omitempty"`
	Sealed      *SealedLocalKey `json:"sealed,omitempty"`
	Version     int             `json:"version,omitempty"`
}
type KeyServiceResponse struct {
	Format        string          `json:"format"`
	Operation     string          `json:"operation"`
	RequestSHA256 string          `json:"requestSHA256"`
	ValidUntil    string          `json:"validUntil"`
	Sealed        *SealedLocalKey `json:"sealed,omitempty"`
	Output        []byte          `json:"output,omitempty"`
}
