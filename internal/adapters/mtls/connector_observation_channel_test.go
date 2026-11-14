package mtls

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type observationCandidatesFunc func(context.Context) (value.APIContextOwnerCandidates, error)

func (f observationCandidatesFunc) ReadContextStartOwners(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return f(ctx)
}
func (f observationCandidatesFunc) ReadOwnerObservationCandidates(ctx context.Context) (value.APIContextOwnerCandidates, error) {
	return f(ctx)
}

type observationMetadataFunc func(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error)

func (f observationMetadataFunc) ObserveCluster(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	return f(ctx, r)
}

// Real TLS 1.3, mutual certificate verification and exporter on a retained
// connection. The local source/Pod/SQL observations remain synthetic; this
// fixture does not qualify native routing or multi-cluster availability.
type observationChannelFixture struct {
	f                                            *connectorPairFixture
	ownerPin                                     value.OwnerObservationPin
	ownerCA                                      ownerTestCA
	owner                                        value.OwnerCertificate
	leaf                                         value.ConnectorCredentialCertificate
	channel                                      *ConnectorObservationChannel
	server                                       tls.ConnectionState
	ctx                                          context.Context
	candidateCalls, registryCalls, metadataCalls int
	revoked, missing                             bool
}

func (x *observationChannelFixture) request() value.ClusterObservationRequest {
	return value.ClusterObservationRequest{RootID: x.ownerPin.RootID, ID: ownerTestID, Challenge: ownerOtherID, ClusterID: x.leaf.Binding.ClusterID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: x.f.clock(), NotAfter: x.f.clock().Add(5 * time.Second)}
}
func (x *observationChannelFixture) probe(t *testing.T, r value.ClusterObservationRequest, n int) contracts.ClusterObservationProbe {
	t.Helper()
	request := value.OwnerObservationRequest{RootID: r.RootID, ID: r.ID, Challenge: r.Challenge, RequestedAt: r.RequestedAt, NotAfter: r.NotAfter}
	channel, err := ownerObservationConnection(&x.server, request)
	if err != nil {
		t.Fatal(err)
	}
	now := x.f.clock()
	config := ownerBootstrapConfiguration(x.ownerPin.Pool, x.ownerCA, now)
	peer := value.PeerCertificate{Binding: x.leaf.Binding, Digest: x.leaf.Digest, NotBefore: x.leaf.NotBefore, NotAfter: x.leaf.NotAfter}
	proof := value.OwnerObservation{Request: request, ConnectionBinding: channel, Connector: peer, Owner: value.AuthenticatedOwner{Certificate: x.owner, EnrollmentID: ownerTestID, Pool: x.ownerPin.Pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, ConfigurationRevision: config.Configuration.Revision, ProtectionDigest: x.ownerPin.ProtectionDigest, VerifiedAt: now, ValidUntil: r.NotAfter}, Workload: value.OwnerObservationWorkload{Pin: x.ownerPin, Binding: x.owner.Binding, Pod: "owner-1", ReplicaSetUID: ownerTestID, WorkloadDigest: artifact.Digest{18}, ObservedAt: now, FreshUntil: r.NotAfter}, ObservedAt: now, FreshUntil: r.NotAfter}
	wire, err := ownerObservationReplyWire(proof)
	if err != nil {
		t.Fatal(err)
	}
	return contracts.ClusterObservationProbe{Format: contracts.ClusterObservationExchangeFormat, ExchangeID: ownerOtherID, Ordinal: n, Owner: wire}
}
