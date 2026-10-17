package contracts

import "encoding/json"

const ConnectorIdentityFormat = "asservat-connector-identity/v1"

// Installation-owned public configuration. The six role names are resolved to
// actual login OIDs by the protected post-activation SQL producer, not accepted
// from an enrollment request or used as DSNs/credentials.
type ConnectorIdentityConfiguration struct {
	Format         string `json:"format"`
	RootID         string `json:"rootID"`
	InstallationID string `json:"installationID"`
	ClusterID      string `json:"clusterID"`
	IssuerEpoch    string `json:"issuerEpoch"`
	PeerID         string `json:"peerID"`
	// Revision changes only with behavioral configuration; BackingRevision is separate.
	Revision          int64                  `json:"revision"`
	Retiring          bool                   `json:"retiring"`
	Suspended         bool                   `json:"suspended"`
	ServerName        string                 `json:"serverName"`
	ClientIssuerRoots [][]byte               `json:"clientIssuerRoots"`
	ServerIssuerRoots [][]byte               `json:"serverIssuerRoots"`
	Roles             ConnectorIdentityRoles `json:"roles"`
	Deployment        ConnectorDeployment    `json:"deployment"`
	Backing           json.RawMessage        `json:"backing"`
}
type ConnectorIdentityRoles struct {
	Source          string `json:"source"`
	Journal         string `json:"journal"`
	Acknowledgement string `json:"acknowledgement"`
	Cleanup         string `json:"cleanup"`
	Verifier        string `json:"verifier"`
	Finalizer       string `json:"finalizer"`
}

type ConnectorDeployment struct {
	Namespace         string `json:"namespace"`
	NamespaceUID      string `json:"namespaceUID"`
	ServiceAccount    string `json:"serviceAccount"`
	AccountUID        string `json:"accountUID"`
	Deployment        string `json:"deployment"`
	DeploymentUID     string `json:"deploymentUID"`
	ServingSlots      int    `json:"servingSlots"`
	RetainedProcesses int    `json:"retainedProcesses"`
}
