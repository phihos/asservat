package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func nativeLeaseFixture() value.NativeLease {
	id := "11111111-1111-4111-8111-111111111111"
	now := time.Now()
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}, Kind: value.NativePrepare, HubPodUID: id, HubProcessEpoch: id, WorkerPodUID: id, WorkerPublicKey: artifact.Digest{1}, SourceVersion: artifact.Digest{2}, ParentID: id, Generation: 1, StartedAt: now, Until: now.Add(4 * time.Second)}
	o.Path = artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: id, StorageRegion: "test", AcquisitionClusterID: id, AcquisitionRegion: "test", ConnectorClusterID: id, ConnectorRegion: "test", HubClusterID: id, HubRegion: "test", WorkerConfiguration: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, HubConfiguration: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{2}}}
	o.Processing = artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, Sequence: 1, StateDigest: artifact.Digest{3}, ObservedAt: now, ValidUntil: o.Until}
	return value.NativeLease{Operation: o, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: o.Until}
}
func TestNativeFrameGateConcurrentShorteningCannotRenew(t *testing.T) {
	l := nativeLeaseFixture()
	short := l.Until.Add(-time.Second)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	g, err := NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) {
		n := calls.Add(1)
		if n == 2 {
			close(blocked)
			<-release
		}
		v := l
		if n >= 3 {
			v.Until = short
		}
		return v, nil
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	done := make(chan value.NativeLease, 1)
	go func() { v, _ := g.Check(context.Background()); done <- v }()
	<-blocked
	v, err := g.Check(context.Background())
	if err != nil || !v.Until.Equal(short) {
		t.Fatal("shorter current bound", err)
	}
	close(release)
	v = <-done
	if !v.Until.Equal(short) {
		t.Fatal("slower old observation renewed lease")
	}
	g.Close()
	if err = g.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestNativeFrameGateOwnsCancellationAndKnownRevocation(t *testing.T) {
	for _, mode := range []string{"cancel", "revoked", "changed-owner", "processing-changed", "worker-configuration-changed", "hub-path-changed", "store-changed"} {
		t.Run(mode, func(t *testing.T) {
			l := nativeLeaseFixture()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			g, err := NewNativeFrameGate(parent, func(ctx context.Context) (value.NativeLease, error) {
				if calls.Add(1) == 1 {
					return l, nil
				}
				switch mode {
				case "cancel":
					cancel()
					<-ctx.Done()
					return l, nil
				case "revoked":
					return value.NativeLease{}, artifact.ErrDownloadUnavailable
				default:
					v := l
					switch mode {
					case "processing-changed":
						v.Operation.Processing.Sequence++
					case "worker-configuration-changed":
						v.Operation.Path.WorkerConfiguration.Generation++
					case "hub-path-changed":
						v.Operation.Path.HubClusterID = "22222222-2222-4222-8222-222222222222"
					case "store-changed":
						v.Operation.Path.StoreID = "22222222-2222-4222-8222-222222222222"
					default:
						v.Operation.Reference.Fence++
					}
					return v, nil
				}
			}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.Check(context.Background()); err == nil {
				t.Fatal("lost current owner accepted")
			}
			g.Close()
			if err = g.Wait(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeFrameGateRequiresProcessingAndExactPath(t *testing.T) {
	for _, name := range []string{"missing-processing", "missing-path", "wrong-target", "expired-processing", "cross-cluster-connector"} {
		t.Run(name, func(t *testing.T) {
			l := nativeLeaseFixture()
			switch name {
			case "missing-processing":
				l.Operation.Processing = artifact.DownloadProcessingProof{}
			case "missing-path":
				l.Operation.Path = artifact.DownloadPath{}
			case "wrong-target":
				l.Operation.Path.TargetClusterID = "22222222-2222-4222-8222-222222222222"
			case "expired-processing":
				l.Operation.Processing.ValidUntil = time.Now().Add(-time.Second)
			case "cross-cluster-connector":
				l.Operation.Path.ConnectorClusterID = "22222222-2222-4222-8222-222222222222"
			}
			gate, e := NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) { return l, nil }, time.Now)
			if gate != nil {
				gate.Close()
			}
			if e == nil {
				t.Fatal("live native gate accepted absent or contradictory processing/path proof")
			}
		})
	}
}
