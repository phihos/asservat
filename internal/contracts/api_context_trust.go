package contracts

import "bytes"

const APIContextTrustFormat = "api-context-work-trust/v1"
const APIContextTrustMaxBytes = 12 << 10

// Public, installation-owned signing trust for one API work purpose. No token,
// private key, URL to fetch keys or caller-selected trust source is accepted.
type APIContextWorkTrustSettings struct {
	Format         string                    `json:"format"`
	RootID         string                    `json:"rootId"`
	InstallationID string                    `json:"installationId"`
	ClusterID      string                    `json:"clusterId"`
	IssuerEpoch    string                    `json:"issuerEpoch"`
	Revision       int64                     `json:"revision"`
	Enabled        bool                      `json:"enabled"`
	Keys           []APIContextWorkPublicKey `json:"keys"`
}
type APIContextWorkPublicKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

func EncodeAPIContextTrust(p APIContextWorkTrustSettings) ([]byte, error) {
	return canonicalAPIContext(p, APIContextTrustMaxBytes)
}
func DecodeAPIContextTrust(b []byte) (APIContextWorkTrustSettings, error) {
	v, e := decodeClosedRPC[APIContextWorkTrustSettings](bytes.NewReader(b), APIContextTrustMaxBytes)
	if e != nil {
		return APIContextWorkTrustSettings{}, ErrAPIContextProtocol
	}
	return v, nil
}
