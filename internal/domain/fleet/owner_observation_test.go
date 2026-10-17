package fleet

import (
	"testing"
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

func TestOwnerObservationKeepsOriginalChildBounds(t *testing.T) {
	now := time.Now().UTC()
	original := ownerObservationFixture(now)
	current := now.Add(10 * time.Millisecond)
	if !original.Valid(current) || !original.Matches(original.Request, original.Workload.Pin, original.ConnectionBinding, original.Connector, original.Owner.Certificate, current) {
		t.Fatal("fixture invalid")
	}
	for _, mode := range []string{"request-end", "owner-end", "workload-end", "peer-end", "own-source", "own-guard", "own-process", "own-rs", "pin-root", "expired", "future", "unopted"} {
		t.Run(mode, func(t *testing.T) {
			v := original
			current := current
			switch mode {
			case "request-end":
				v.Request.NotAfter = v.FreshUntil.Add(-time.Nanosecond)
			case "owner-end":
				v.Owner.ValidUntil = v.FreshUntil.Add(-time.Nanosecond)
			case "workload-end":
				v.Workload.FreshUntil = v.FreshUntil.Add(-time.Nanosecond)
			case "peer-end":
				v.Connector.NotAfter = v.FreshUntil.Add(-time.Nanosecond)
			case "own-source":
				v.Owner.ConfigurationRevision.UID = observationOtherID
			case "own-guard":
				v.Owner.ProtectionDigest = artifact.Digest{9}
			case "own-process":
				v.Workload.Binding.ProcessEpoch = observationTestID
			case "own-rs":
				v.Workload.ReplicaSetUID = observationOtherID
			case "pin-root":
				v.Request.RootID = observationOtherID
			case "expired":
				current = v.FreshUntil
			case "future":
				v.ObservedAt = current.Add(time.Nanosecond)
			case "unopted":
				v.Workload.Pin.Pool.NativeBootstrap = ""
			}
			if v.Valid(current) {
				t.Fatal("changed or extended original proof accepted")
			}
		})
	}
}
func TestOwnerObservationCannotMoveBetweenCallsOrConnections(t *testing.T) {
	now := time.Now().UTC()
	v := ownerObservationFixture(now)
	current := now.Add(10 * time.Millisecond)
	for _, mode := range []string{"request-id", "challenge", "request-start", "request-end", "channel", "client-leaf", "server-leaf", "template", "source"} {
		t.Run(mode, func(t *testing.T) {
			r, p, ch, client, server := v.Request, v.Workload.Pin, v.ConnectionBinding, v.Connector, v.Owner.Certificate
			switch mode {
			case "request-id":
				r.ID = observationOtherID
			case "challenge":
				r.Challenge = observationTestID
			case "request-start":
				r.RequestedAt = r.RequestedAt.Add(time.Nanosecond)
			case "request-end":
				r.NotAfter = r.NotAfter.Add(time.Nanosecond)
			case "channel":
				ch = artifact.Digest{9}
			case "client-leaf":
				client.Digest = artifact.Digest{9}
			case "server-leaf":
				server.Digest = artifact.Digest{9}
			case "template":
				p.TemplateDigest = artifact.Digest{9}
			case "source":
				p.SourceUID = observationOtherID
			}
			if v.Matches(r, p, ch, client, server, current) {
				t.Fatal("proof reused outside original exact tuple")
			}
		})
	}
}
