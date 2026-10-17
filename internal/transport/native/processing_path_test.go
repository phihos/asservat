package native_test

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic policy/processing authority only. These tests qualify the actual
// protocol/gates, not production installation acceptance or SQL decisions.
func syntheticProcessingPath(o value.NativeOperation) value.NativeOperation {
	id := o.Reference.InstallationID
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{7}}
	o.Path = artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: id, StorageRegion: "fixture", AcquisitionClusterID: id, AcquisitionRegion: "fixture", ConnectorClusterID: id, ConnectorRegion: "fixture", HubClusterID: id, HubRegion: "fixture", WorkerConfiguration: rev, HubConfiguration: rev}
	o.Processing = artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Sequence: 1, StateDigest: artifact.Digest{8}, ObservedAt: o.StartedAt, ValidUntil: o.Until}
	return o
}
