package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"encoding/json"
	"testing"
	"time"
)

func TestNativeCompletionRequiresCurrentExactOpenGeneration(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	key := "10000000-0000-4000-8000-000000000001"
	rev := identity.Revision{UID: key, Generation: 1, Digest: artifact.Digest{7}}
	a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: key, ArtifactID: key, CaptureID: key, ClusterID: key, NamespaceUID: key, WorkloadUID: key, PodUID: key, Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}, PermissionEpoch: key, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: rev, CheckedAt: n, ValidUntil: n.Add(4 * time.Second), AccessUntil: n.Add(time.Hour)}
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: key, SessionID: key, WorkerID: key, OperationID: key, Fence: 2}, Kind: value.NativeObserve, HubPodUID: key, HubProcessEpoch: key, WorkerPodUID: key, WorkerPublicKey: artifact.Digest{1}, SourceVersion: a.Scope.Version, ParentID: key, Generation: 1, StartedAt: n, Until: a.ValidUntil}
	o.Path = artifact.DownloadPath{ID: key, TargetClusterID: key, StoreID: key, StorageRegion: "test", AcquisitionClusterID: key, AcquisitionRegion: "test", ConnectorClusterID: key, ConnectorRegion: "test", HubClusterID: key, HubRegion: "test", WorkerConfiguration: rev, HubConfiguration: rev}
	o.Processing = artifact.DownloadProcessingProof{RootID: key, Epoch: key, CaptureID: key, Location: artifact.Location{ClusterID: key, ArtifactID: key, AttemptID: key}, Sequence: 1, StateDigest: artifact.Digest{3}, ObservedAt: n, ValidUntil: o.Until}
	l := value.NativeLease{Operation: o, Certificate: artifact.Digest{5}, Sequence: 1, ObservedAt: n, Until: o.Until}
	ob, _ := json.Marshal(o)
	ab, _ := json.Marshal(a)
	row := custodydb.DownloadNativeOwner{WorkerID: id(key), RootID: id(key), OperationID: id(key), Fence: 2, OperationJson: ob, AuthorityJson: ab, LeaseSequence: 1, LeaseStarted: ts(n), LeaseUntil: ts(o.Until)}
	if !nativeCompletionRecordValid(row, l, n) {
		t.Fatal("current exact original row denied")
	}
	tests := []struct {
		name   string
		change func(*custodydb.DownloadNativeOwner, *value.NativeLease, *time.Time)
	}{
		{"already-closed", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) { r.Closed = true }},
		{"retired", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) { r.RetiredAt = ts(n) }},
		{"different-operation", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) {
			r.OperationID = id("10000000-0000-4000-8000-000000000002")
		}},
		{"replacement-fence", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) { r.Fence++ }},
		{"old-lease-sequence", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) { r.LeaseSequence++ }},
		{"shortened-row", func(r *custodydb.DownloadNativeOwner, _ *value.NativeLease, _ *time.Time) {
			r.LeaseUntil = ts(n.Add(time.Second))
		}},
		{"expired-after-lock", func(_ *custodydb.DownloadNativeOwner, _ *value.NativeLease, now *time.Time) { *now = o.Until }},
		{"different-parent", func(_ *custodydb.DownloadNativeOwner, l *value.NativeLease, _ *time.Time) {
			l.Operation.ParentID = "10000000-0000-4000-8000-000000000002"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, c, now := row, l, n
			tc.change(&r, &c, &now)
			if nativeCompletionRecordValid(r, c, now) {
				t.Fatal("historical/replaced row certified completion")
			}
		})
	}
}
