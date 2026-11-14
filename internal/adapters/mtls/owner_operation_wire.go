package mtls

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerOperationReplyWire(pin value.OwnerObservationPin, request value.OwnerObservationRequest, id string, ordinal int, channel artifact.Digest, peer value.PeerCertificate, leaf value.OwnerCertificate, facts value.OwnerObservationNativeFacts, r value.OwnerRegistrationObservation, end time.Time, now time.Time) (contracts.OwnerObservationOperationReply, error) {
	var z contracts.OwnerObservationOperationReply
	digest, err := ownerObservationPinDigest(pin)
	if err != nil || !authorization.UUID(id) || channel == (artifact.Digest{}) || ordinal < 1 || ordinal > 4 || facts.Final != (ordinal == 4) || !facts.Valid(now) || facts.Pin != pin || !value.SameOwnerObservationRequest(request, facts.Request) || !r.Valid(now) || r.Certificate != leaf || !ownerOperationPeerMatches(facts, r) || !peer.Valid(now) {
		return z, value.ErrDenied
	}
	until := identity.Earlier(end, identity.Earlier(facts.FreshUntil, peer.NotAfter))
	if !now.Before(until) {
		return z, value.ErrUnavailable
	}
	var work artifact.Digest
	for _, p := range facts.Peers {
		if p.Binding == leaf.Binding {
			work = p.WorkloadDigest
		}
	}
	f := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	rev := r.Configuration.Configuration.Revision
	return contracts.OwnerObservationOperationReply{Format: contracts.OwnerObservationOperationFormat, Request: observationOperationRequestWire(request), Ordinal: ordinal, BracketID: id, ConnectionBinding: ownerObservationHex(channel), ConnectorLeaf: ownerObservationHex(peer.Digest), OwnerLeaf: ownerObservationHex(leaf.Digest), PinDigest: ownerObservationHex(digest), EnrollmentID: r.Enrollment.ID, Pod: r.Enrollment.Pod, ReplicaSetUID: r.Enrollment.ReplicaSetUID, Configuration: contracts.APIContextRevision{UID: rev.UID, Generation: rev.Generation, Digest: ownerObservationHex(rev.Digest)}, WorkloadDigest: ownerObservationHex(work), NativeStartedAt: f(facts.ObservedAt), NativeUntil: f(until), RegistrationObservedAt: f(r.ObservedAt), RegistrationUntil: f(identity.Earlier(r.FreshUntil, until)), Final: facts.Final}, nil
}

// This is a v2 delegated correlation, not AuthenticatedOwner or a v1 full native
// observation. It is accepted only on the actual TLS connection with independent
// current SQL/issuer validation. The initial native dates remain unchanged.
type ownerOperationObservation struct {
	wire           contracts.OwnerObservationOperationReply
	owner          value.OwnerCertificate
	revision       identity.Revision
	configuration  value.OwnerConfiguration
	started, until time.Time
	nativeUntil    time.Time
}
