package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const observationTestID = "11111111-1111-4111-8111-111111111111"
const observationOtherID = "22222222-2222-4222-8222-222222222222"

func ownerObservationFixture(now time.Time) OwnerObservation {
	p := OwnerPool{InstallationID: observationTestID, ClusterID: observationTestID, IssuerEpoch: observationTestID, Namespace: "hub", NamespaceUID: observationTestID, Service: "hub", ServiceUID: observationTestID, Deployment: "hub", DeploymentUID: observationTestID, ServiceAccount: "hub", AccountUID: observationTestID, Port: 9443, NativePort: 9444, NativeBootstrap: OwnerBootstrapProfile}
	b := OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: observationTestID, ProcessEpoch: observationOtherID}
	pin := OwnerObservationPin{RootID: observationTestID, SourceUID: observationTestID, Pool: p, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}
	r := OwnerObservationRequest{RootID: pin.RootID, ID: observationTestID, Challenge: observationOtherID, RequestedAt: now, NotAfter: now.Add(4 * time.Second)}
	owner := AuthenticatedOwner{Certificate: OwnerCertificate{Binding: b, Usage: "server", Digest: artifact.Digest{4}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute)}, EnrollmentID: observationTestID, Pool: p, Pod: "hub-1", ReplicaSetUID: observationTestID, ConfigurationRevision: identity.Revision{UID: pin.SourceUID, Generation: 1, Digest: artifact.Digest{5}}, ProtectionDigest: pin.ProtectionDigest, VerifiedAt: now.Add(time.Millisecond), ValidUntil: now.Add(3 * time.Second)}
	peer := PeerCertificate{Binding: PeerBinding{InstallationID: p.InstallationID, ClusterID: observationOtherID, IssuerEpoch: p.IssuerEpoch, PeerID: observationTestID, Role: ConnectorPeer}, Digest: artifact.Digest{6}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(20 * time.Minute)}
	workload := OwnerObservationWorkload{Pin: pin, Binding: b, Pod: owner.Pod, ReplicaSetUID: owner.ReplicaSetUID, WorkloadDigest: artifact.Digest{7}, ObservedAt: now.Add(2 * time.Millisecond), FreshUntil: now.Add(2 * time.Second)}
	return OwnerObservation{Request: r, ConnectionBinding: artifact.Digest{8}, Connector: peer, Owner: owner, Workload: workload, ObservedAt: now.Add(3 * time.Millisecond), FreshUntil: workload.FreshUntil}
}
