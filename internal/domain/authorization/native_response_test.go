package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestNativeResponsePinsInitialProcessingIdentitySeparatelyFromDisclosureLease(t *testing.T) {
	n := time.Now()
	id := "11111111-1111-4111-8111-111111111111"
	revision := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	op := NativeOperation{Reference: NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}, Kind: NativeResponse, HubPodUID: id, HubProcessEpoch: id, WorkerPodUID: id, WorkerPublicKey: artifact.Digest{1}, SourceVersion: artifact.Digest{2}, ParentID: id, Generation: 1, StartedAt: n, Until: n.Add(20 * time.Second), Path: artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: id, StorageRegion: "test", AcquisitionClusterID: id, AcquisitionRegion: "test", ConnectorClusterID: id, ConnectorRegion: "test", HubClusterID: id, HubRegion: "test", WorkerConfiguration: revision, HubConfiguration: revision}, Processing: artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Sequence: 1, StateDigest: artifact.Digest{3}, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}}
	if !op.CurrentValid(n.Add(12 * time.Second)) {
		t.Fatal("response operation identity expired with initial observation")
	}
	if op.Processing.Valid(n.Add(12 * time.Second)) {
		t.Fatal("old processing observation became fresh")
	}
	if (NativeLease{Operation: op, Certificate: artifact.Digest{4}, Sequence: 1, ObservedAt: n, Until: n.Add(5 * time.Second)}).Valid(n.Add(12 * time.Second)) {
		t.Fatal("expired disclosure lease revived")
	}
	bad := op
	bad.Processing.ValidUntil = n
	if bad.CurrentValid(n) {
		t.Fatal("unqualified initial processing identity")
	}
	bad = op
	bad.Until = n.Add(time.Minute + time.Microsecond)
	if bad.Valid() {
		t.Fatal("response original operation exceeded fixed ceiling")
	}
	long := op
	long.Until = n.Add(time.Minute)
	if !long.Valid() || !long.CurrentValid(n.Add(25*time.Second)) {
		t.Fatal("bounded paced window refused")
	}
	if NativeLeaseWindow(NativeResponse) != 5*time.Second {
		t.Fatal("conversation enlarged disclosure lease")
	}
	if op.CurrentValid(n.Add(21 * time.Second)) {
		t.Fatal("new ceiling extended old operation")
	}
	if op.CurrentValid(op.Until) {
		t.Fatal("response operation deadline revived")
	}
}
