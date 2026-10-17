package contracts

type WorkTrustSettings struct {
	Version     string         `json:"version"`
	Revision    int64          `json:"revision"`
	ClusterID   string         `json:"clusterID"`
	IssuerEpoch string         `json:"issuerEpoch"`
	Keys        []WorkTrustKey `json:"keys"`
}
type WorkTrustKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}
