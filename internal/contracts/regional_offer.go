package contracts

import (
	"encoding/json"
	"errors"
	"strings"
)

// RegionalOffer is the hub's public offer to regional installers (ADR-193):
// the federation endpoint and roots and the installation-wide connector
// values a regional connector source must name. It holds no credential and
// confers no enrollment authority; enrollment needs a fleet operator's
// audited bootstrap.
const RegionalOfferFormat = "asservat-regional-offer/v1"
const RegionalOfferFile = "regional-offer.json"

type RegionalOffer struct {
	Format           string `json:"format"`
	InstallationID   string `json:"installationID"`
	HubClusterID     string `json:"hubClusterID"`
	PermissionRootID string `json:"permissionRootID"`
	IssuerEpoch      string `json:"issuerEpoch"`
	// Federation is what the connector dials: the external endpoint, the
	// server name and the roots of the operator's serving certificate.
	Federation RegionalHubEndpoint `json:"federation"`
	// ConnectorServerSuffix and ConnectorIssuerRoots constrain the connector
	// leaves; Roles are the six installation-wide connector duty logins.
	ConnectorServerSuffix string                 `json:"connectorServerSuffix"`
	ConnectorIssuerRoots  [][]byte               `json:"connectorIssuerRoots"`
	Roles                 ConnectorIdentityRoles `json:"roles"`
	// ConnectorBacking is the hub-decided root backing the regional source
	// names unchanged (FederationConnector.Backing).
	ConnectorBacking json.RawMessage `json:"connectorBacking"`
	Image            string          `json:"image"`
	// Owners is where regional context starts reach the hub's owners: the
	// exposed native address and the accepted owner pool (ADR-196).
	Owners *RegionalContextOwners `json:"owners,omitempty"`
	// KeyService is the hub's artifact key service (ADR-198).
	KeyService *RegionalWrapService `json:"keyService,omitempty"`
	// WorkKey verifies the hub's signed context-start work, and
	// EvidenceStore is where regional artifacts are written (ADR-196
	// decision 7). An offer naming Owners, KeyService, WorkKey and
	// EvidenceStore installs the regional executor; one naming none installs
	// the plain connector; any other combination is refused.
	WorkKey       *APIContextWorkPublicKey `json:"workKey,omitempty"`
	EvidenceStore *RegionalEvidenceStore   `json:"evidenceStore,omitempty"`
	// Capacity is the ADR-197 regional capacity section. It requires the
	// executor section.
	Capacity *RegionalCapacityOffer `json:"capacity,omitempty"`
}

// RegionalCapacityOffer is what a region needs to serve the hub-worker's v2
// capacity observation (ADR-197): the owner's operation address, the owner
// pin the standby verifies and the hub's capacity selector keys.
type RegionalCapacityOffer struct {
	OperationAddress string                   `json:"operationAddress"`
	Owner            RegionalOwnerObservation `json:"owner"`
	Keys             []string                 `json:"keys"`
}

// RegionalOwnerObservation is the hub owner's observation pin: its accepted
// source and its workload's template, image and guard digests (hex).
type RegionalOwnerObservation struct {
	SourceUID        string `json:"sourceUID"`
	TemplateDigest   string `json:"templateDigest"`
	ImageDigest      string `json:"imageDigest"`
	ProtectionDigest string `json:"protectionDigest"`
}

// RegionalExecutorOffered reports whether the offer names the complete
// executor section (true), none of it (false), or only part of it (error).
func (o RegionalOffer) RegionalExecutorOffered() (bool, error) {
	n := 0
	for _, set := range []bool{o.Owners != nil, o.KeyService != nil, o.WorkKey != nil, o.EvidenceStore != nil} {
		if set {
			n++
		}
	}
	if n != 0 && n != 4 || o.Capacity != nil && n != 4 {
		return false, ErrRegionalOfferPartial
	}
	return n == 4, nil
}

var ErrRegionalOfferPartial = errors.New("regional offer names only part of the executor section")

// RegionalServingSlots and RegionalRetainedProcesses are the connector
// deployment shape installer-cluster writes into every regional source; the
// hub-decided backing must support it.
const (
	RegionalServingSlots      = 2
	RegionalRetainedProcesses = 8
)

func RegionalOfferName(installationID string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-regional-offer"
}
