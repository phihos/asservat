package contracts

import "bytes"

// ConnectorAPIContextSettings is a separately pinned immutable public source.
// It is never populated from an exchange Hello, capture or connector registration.
type ConnectorAPIContextSettings struct {
	Format                   string                 `json:"format"`
	RootID                   string                 `json:"rootId"`
	InstallationID           string                 `json:"installationId"`
	ClusterID                string                 `json:"clusterId"`
	IssuerEpoch              string                 `json:"issuerEpoch"`
	ConnectorRevision        APIContextRevision     `json:"connectorRevision"`
	Namespace                string                 `json:"namespace"`
	NamespaceUID             string                 `json:"namespaceUID"`
	Account                  string                 `json:"account"`
	AccountUID               string                 `json:"accountUID"`
	Deployment               string                 `json:"deployment"`
	DeploymentUID            string                 `json:"deploymentUID"`
	ImageDigest              string                 `json:"imageDigest"`
	TemplateDigest           string                 `json:"templateDigest"`
	ProjectionDigest         string                 `json:"projectionDigest"`
	WorkloadProtectionDigest string                 `json:"workloadProtectionDigest"`
	CapacityAccount          string                 `json:"capacityAccount"`
	CapacityAccountUID       string                 `json:"capacityAccountUID"`
	Inputs                   []ConnectorAPIInput    `json:"inputs"`
	StartGuard               ConnectorAPIStartGuard `json:"startGuard"`
}

type ConnectorAPIInput struct {
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	// DedicatedToAPI affirms the protected installer assigned the entire Secret
	// to this API role. GET authorization cannot be restricted to its metadata.
	DedicatedToAPI bool `json:"dedicatedToAPI,omitempty"`
}

type ConnectorAPIStartGuard struct {
	Name                   string `json:"name"`
	PolicyUID              string `json:"policyUID"`
	PolicyGeneration       int64  `json:"policyGeneration"`
	BindingUID             string `json:"bindingUID"`
	BindingResourceVersion string `json:"bindingResourceVersion"`
}

const ConnectorAPIContextFormat = "connector-api-context/v1"
const ConnectorAPIContextSettingsBytes = 16 << 10

func EncodeConnectorAPIContextSettings(p ConnectorAPIContextSettings) ([]byte, error) {
	return canonicalAPIContext(p, ConnectorAPIContextSettingsBytes)
}
func DecodeConnectorAPIContextSettings(raw []byte) (ConnectorAPIContextSettings, error) {
	return decodeClosedRPC[ConnectorAPIContextSettings](bytes.NewReader(raw), ConnectorAPIContextSettingsBytes)
}
