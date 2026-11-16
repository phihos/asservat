package contracts

// RegionalOffer is the hub's public offer to connectors: what a connector's
// regional executor needs from the hub (owners, key service, evidence store).
// The hub writes it into ConfigMap <name>-regional-offer; the federation
// sends it with each connector's settings on connect. It holds no
// credential.
const RegionalOfferFormat = "asservat-regional-offer/v1"
const RegionalOfferFile = "regional-offer.json"

type RegionalOffer struct {
	Format           string `json:"format"`
	InstallationID   string `json:"installationID"`
	HubClusterID     string `json:"hubClusterID"`
	PermissionRootID string `json:"permissionRootID"`
	IssuerEpoch      string `json:"issuerEpoch"`
	Image            string `json:"image"`
	// Owners is where context starts reach the hub's owners: the hub-api
	// native address and the accepted owner pool (ADR-196).
	Owners *RegionalContextOwners `json:"owners"`
	// KeyService is the hub's artifact key service (ADR-198).
	KeyService *RegionalWrapService `json:"keyService"`
	// EvidenceStore is where regional artifacts are written (ADR-196
	// decision 7).
	EvidenceStore *RegionalEvidenceStore `json:"evidenceStore"`
}

// Complete reports whether the offer names every executor section.
func (o RegionalOffer) Complete() bool {
	return o.Owners != nil && o.KeyService != nil && o.EvidenceStore != nil
}

// RegionalServingSlots and RegionalRetainedProcesses are the connector
// deployment shape of every catalog entry.
const (
	RegionalServingSlots      = 2
	RegionalRetainedProcesses = 8
)
