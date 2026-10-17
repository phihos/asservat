package contracts

const DownloadEnvironmentFormat = "asservat-download-environment/v1"

// DownloadEnvironmentFile is the processing source ConfigMap key.
const DownloadEnvironmentFile = "download-environment.json"
const DownloadEnvironmentMaxBytes = 128 << 10

// Private administrator policy. No endpoint, credential, raw artifact content,
// subject search index, or caller-selected processing placement is accepted.
type DownloadEnvironmentSettings struct {
	Format           string                      `json:"format"`
	RootID           string                      `json:"rootID"`
	InstallationID   string                      `json:"installationID"`
	RecoveryEpoch    string                      `json:"recoveryEpoch"`
	Revision         int64                       `json:"revision"`
	Suspended        bool                        `json:"suspended"`
	PermittedRegions []string                    `json:"permittedRegions"`
	Paths            []DownloadEnvironmentPath   `json:"paths"`
	Clients          []DownloadEnvironmentClient `json:"clients"`
	Operators        []ProcessingOperator        `json:"operators"`
}
type DownloadEnvironmentRevision struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	SHA256     string `json:"sha256"`
}
type DownloadEnvironmentPath struct {
	ID                   string                      `json:"id"`
	TargetClusterID      string                      `json:"targetClusterID"`
	StoreID              string                      `json:"storeID"`
	StorageRegion        string                      `json:"storageRegion"`
	AcquisitionClusterID string                      `json:"acquisitionClusterID"`
	AcquisitionRegion    string                      `json:"acquisitionRegion"`
	ConnectorClusterID   string                      `json:"connectorClusterID"`
	ConnectorRegion      string                      `json:"connectorRegion"`
	HubClusterID         string                      `json:"hubClusterID"`
	HubRegion            string                      `json:"hubRegion"`
	WorkerConfiguration  DownloadEnvironmentRevision `json:"workerConfiguration"`
	HubConfiguration     DownloadEnvironmentRevision `json:"hubConfiguration"`
}
type DownloadEnvironmentClient struct {
	Issuer         string   `json:"issuer"`
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	DataClasses    []string `json:"dataClasses"`
	PrivacyClasses []string `json:"privacyClasses"`
	EvidenceTypes  []string `json:"evidenceTypes"`
	Purposes       []string `json:"purposes"`
	PathIDs        []string `json:"pathIDs"`
}
type ProcessingOperator struct {
	ClientID string `json:"clientID"`
	Issuer   string `json:"issuer"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
}
