package mtls

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	permissions "asservat.local/asservat/internal/domain/authorization"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// Actual process-owned P-256 credentials and the current registry/route/guard
// authenticator, with explicit synthetic accepted deployment observations.
func TestNativeHubPlacementRequiresActualCurrentServingIdentity(t *testing.T) {
	for _, mode := range []string{"valid", "other-hub-cluster", "other-hub-configuration", "other-pod", "other-process", "closed-key", "expired-after-route", "configuration-changed-after-route"} {
		t.Run(mode, func(t *testing.T) {
			server, fixture := newOwnerCredentialFixture(t, "server")
			if err := server.Enroll(context.Background()); err != nil {
				t.Fatal(err)
			}
			certificate, err := server.Certificate()
			if err != nil {
				t.Fatal(err)
			}
			original, err := fixture.ReadOwnerRegistration(context.Background(), certificate)
			if err != nil {
				t.Fatal(err)
			}
			n := fixture.now()
			p := original.Configuration.Configuration.Pool
			revision := original.Configuration.Configuration.Revision
			path := artifact.DownloadPath{ID: ownerTestID, TargetClusterID: ownerTestID, StoreID: ownerTestID, StorageRegion: "store", AcquisitionClusterID: ownerTestID, AcquisitionRegion: "worker", ConnectorClusterID: ownerTestID, ConnectorRegion: "connector", HubClusterID: p.ClusterID, HubRegion: "hub", WorkerConfiguration: revision, HubConfiguration: revision}
			proof := artifact.DownloadProcessingProof{RootID: ownerTestID, Epoch: ownerTestID, CaptureID: ownerTestID, Location: artifact.Location{ClusterID: ownerTestID, ArtifactID: ownerTestID, AttemptID: ownerTestID}, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: n, ValidUntil: n.Add(2 * time.Second)}
			operation := permissions.NativeOperation{Path: path, Processing: proof, Reference: permissions.NativeReference{InstallationID: p.InstallationID, SessionID: ownerTestID, WorkerID: ownerTestID, OperationID: ownerTestID, Fence: 1}, Kind: permissions.NativePrepare, HubPodUID: certificate.Binding.PodUID, HubProcessEpoch: certificate.Binding.ProcessEpoch, WorkerPodUID: ownerTestID, WorkerPublicKey: artifact.Digest{2}, SourceVersion: artifact.Digest{3}, ParentID: ownerTestID, Generation: 1, StartedAt: n, Until: proof.ValidUntil}
			reads := 0
			registry := forwardRegistry(func(ctx context.Context, c fleet.OwnerCertificate) (fleet.OwnerRegistrationObservation, error) {
				reads++
				out, err := fixture.ReadOwnerRegistration(ctx, c)
				if mode == "configuration-changed-after-route" && reads > 1 {
					out.Configuration.Configuration.Revision.Generation++
				}
				return out, err
			})
			routes := forwardRoutes(func(_ context.Context, b fleet.OwnerBinding) (fleet.OwnerRoute, error) {
				if mode == "expired-after-route" {
					fixture.clock.Store(n.Add(3 * time.Second).UnixNano())
				}
				now := fixture.now()
				cfg := fleet.OwnerConfigurationObservation{Configuration: original.Configuration.Configuration.Clone(), ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
				return fleet.OwnerRoute{Configuration: cfg, Endpoint: fleet.OwnerEndpoint{Binding: b, Pool: p, Pod: original.Enrollment.Pod, ReplicaSetUID: original.Enrollment.ReplicaSetUID, Addresses: []string{"10.0.0.8"}, ObservedAt: now, FreshUntil: cfg.FreshUntil}, ObservedAt: now, FreshUntil: cfg.FreshUntil}, nil
			})
			guard := forwardGuard(func(_ context.Context, p fleet.OwnerPool) (fleet.OwnerProtection, error) {
				now := fixture.now()
				return fleet.OwnerProtection{Pool: p, Digest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
			})
			peers := OwnerRequestPeers{Server: server, Authenticator: &app.OwnerAuthenticator{Registry: registry, Routes: routes, Protection: guard, Now: fixture.now}}
			switch mode {
			case "other-hub-cluster":
				operation.Path.HubClusterID = ownerOtherID
			case "other-hub-configuration":
				operation.Path.HubConfiguration.Generation++
			case "other-pod":
				operation.HubPodUID = ownerOtherID
			case "other-process":
				operation.HubProcessEpoch = ownerOtherID
			case "closed-key":
				server.Close()
			}
			until, err := peers.CheckNativeHub(context.Background(), operation)
			if mode == "valid" {
				if err != nil || !until.After(fixture.now()) || until.After(operation.Until) {
					t.Fatal("actual accepted serving path rejected", err)
				}
			} else if err == nil || !until.IsZero() {
				t.Fatal("wrong or expired processor accepted", mode, until)
			}
		})
	}
}
