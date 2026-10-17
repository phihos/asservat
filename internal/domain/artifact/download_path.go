package artifact

import "asservat.local/asservat/internal/domain/identity"

// DownloadPath is protected installation placement, not a developer-selected
// route. Region labels are accepted locality assertions, never S3 signing-region
// discovery. Each class of actual processor is represented independently.
type DownloadPath struct {
	ID, TargetClusterID, StoreID            string
	StorageRegion                           string
	AcquisitionClusterID, AcquisitionRegion string
	ConnectorClusterID, ConnectorRegion     string
	HubClusterID, HubRegion                 string
	WorkerConfiguration, HubConfiguration   identity.Revision
}

func (p DownloadPath) Valid() bool {
	return uuid(p.ID) && uuid(p.TargetClusterID) && uuid(p.StoreID) &&
		uuid(p.AcquisitionClusterID) && p.ConnectorClusterID == p.AcquisitionClusterID && uuid(p.HubClusterID) &&
		identity.Text(p.StorageRegion, 63) && identity.Text(p.AcquisitionRegion, 63) && identity.Text(p.ConnectorRegion, 63) && identity.Text(p.HubRegion, 63) &&
		p.WorkerConfiguration.Valid() && p.HubConfiguration.Valid() && uuid(p.WorkerConfiguration.UID) && uuid(p.HubConfiguration.UID)
}
