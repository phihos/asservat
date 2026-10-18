package contracts

import (
	"crypto/sha256"
	"fmt"
)

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

// DownloadEnvironmentPathTemplate is every DownloadEnvironmentPath field except
// the ID and the target cluster (ADR-204 decision 4). Regional clusters join
// after installation, so the hub derives one path per joined cluster from the
// guarded cluster catalog with DownloadPathFor.
type DownloadEnvironmentPathTemplate struct {
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

// DownloadPathFor derives the one path of a joined target cluster. Its ID is a
// UUID derived from the installation and the target cluster, so every
// component that knows the template and the cluster derives the same path.
func DownloadPathFor(installationID string, t DownloadEnvironmentPathTemplate, targetClusterID string) DownloadEnvironmentPath {
	d := sha256.Sum256([]byte("asservat-download-path/v1\x00" + installationID + "\x00" + targetClusterID))
	d[6] = d[6]&0x0f | 0x80 // version 8 (custom)
	d[8] = d[8]&0x3f | 0x80 // RFC 9562 variant
	id := fmt.Sprintf("%x-%x-%x-%x-%x", d[0:4], d[4:6], d[6:8], d[8:10], d[10:16])
	return DownloadEnvironmentPath{ID: id, TargetClusterID: targetClusterID, StoreID: t.StoreID, StorageRegion: t.StorageRegion,
		AcquisitionClusterID: t.AcquisitionClusterID, AcquisitionRegion: t.AcquisitionRegion, ConnectorClusterID: t.ConnectorClusterID, ConnectorRegion: t.ConnectorRegion,
		HubClusterID: t.HubClusterID, HubRegion: t.HubRegion, WorkerConfiguration: t.WorkerConfiguration, HubConfiguration: t.HubConfiguration}
}
